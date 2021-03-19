package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"gitlab.jaztec.info/jaztec/microservice-example/proto"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-session/session"

	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/gorilla/mux"
	"gitlab.jaztec.info/jaztec/microservice-example/auth"
	"gitlab.jaztec.info/jaztec/microservice-example/ca"
)

//.well-known/jwks.json

//go:embed static/*
var static embed.FS

func main() {
	clientAddr := os.Getenv("CLIENT_ADDR")
	if clientAddr == "" {
		panic("No valid CLIENT_ADDR received")
	}

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		panic("No valid LISTEN_ADDR received")
	}

	userAddr := os.Getenv("USER_ADDR")
	if userAddr == "" {
		panic("No valid USER_ADDR received")
	}

	caClient, err := ca.NewCAClient("auth_service")
	if err != nil {
		panic(err)
	}

	certPool, err := caClient.CertPool(context.Background(), "auth_service")
	if err != nil {
		panic(err)
	}

	crt, _, err := caClient.Certificate(context.Background(), "auth_service", ca.Client)
	if err != nil {
		panic(err)
	}

	tlsConfig := &tls.Config{
		RootCAs:      certPool,
		Certificates: []tls.Certificate{crt},
	}

	// client memory store
	clientStore, err := auth.NewStore(clientAddr, tlsConfig)
	if err != nil {
		panic(err)
	}
	defer clientStore.Close()

	conn, err := grpc.Dial(userAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		panic(fmt.Errorf("error dialing %s, got error: %w", userAddr, err))
	}
	userClient := proto.NewUserServiceClient(conn)

	srv := createServer(listenAddr, userClient, getManager(clientStore), userAuthenticationHandler(userClient))

	log.Fatal(srv.ListenAndServe())
}

func createServer(listenAddr string, userClient proto.UserServiceClient, manager oauth2.Manager, userHandler server.UserAuthorizationHandler) *http.Server {
	srv := server.NewDefaultServer(manager)

	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	srv.UserAuthorizationHandler = userHandler

	router := mux.NewRouter()

	httpServer := &http.Server{
		Addr:           listenAddr,
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	router.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	router.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			log.Print(fmt.Errorf("error handling token: %+v", err))
		}
	})

	router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		s, err := session.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if r.Method == "POST" {
			if r.Form == nil {
				if err := r.ParseForm(); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
			fmt.Println(r.Form)

			resp, err := userClient.UserByUsernamePassword(r.Context(), &proto.UsernamePasswordRequest{
				Username: r.Form.Get("username"),
				Password: r.Form.Get("password"),
			})
			if err != nil {
				log.Println(err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if resp.Error != nil {
				log.Println(resp.Error.Message)
				http.Error(w, resp.Error.Message, http.StatusInternalServerError)
				return
			}
			fmt.Println(resp.User)

			s.Set("userId", resp.User.UserID)
			s.Save()

			w.Header().Set("Location", "/auth")
			w.WriteHeader(http.StatusFound)
			return
		}

		html(w, r, "static/login.html")
	})

	router.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		s, err := session.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userId, ok := s.Get("userId")
		if !ok {
			http.Error(w, "userId not found", http.StatusInternalServerError)
			return
		}

		resp, err := userClient.UserByID(r.Context(), &proto.UserByIdRequest{Id: userId.(string)})
		if err != nil {
			http.Error(w, "userId not found", http.StatusInternalServerError)
			return
		}

		if resp.Error != nil {
			http.Error(w, resp.Error.Message, int(resp.Error.Code))
			return
		}

		html(w, r, "static/auth.html")
	})

	return httpServer
}

func getManager(clientStore *auth.Store) oauth2.Manager {
	client, err := ca.NewCAClient("auth_service")
	if err != nil {
		panic(err)
	}
	_, key, err := client.Certificate(context.Background(), "jwt_token", ca.Client)
	if err != nil {
		panic(err)
	}

	manager := manage.NewDefaultManager()
	// token memory store
	manager.MustTokenStorage(store.NewMemoryTokenStore())
	manager.MapAccessGenerate(generates.NewJWTAccessGenerate(time.Now().String(), key, jwt.SigningMethodHS512))

	manager.MapClientStorage(clientStore)
	return manager
}

func html(w http.ResponseWriter, r *http.Request, path string) {
	f, err := static.Open(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	content, err := ioutil.ReadAll(f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	reader := bytes.NewReader(content)
	http.ServeContent(w, r, fi.Name(), fi.ModTime(), reader)
}

func userAuthenticationHandler(client proto.UserServiceClient) server.UserAuthorizationHandler {
	return func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		r.ParseForm()
		log.Println("userAuthenticationHandler:", r.Form)

		return "", errors.New("userAuthenticationHandler: Not yet implemented")
	}
}
