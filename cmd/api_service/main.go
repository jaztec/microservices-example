package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/oauth2/jws"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/graphql-go/graphql"
	"github.com/jaztec/microservice-example/ca"
	"github.com/jaztec/microservice-example/proto"
)

//go:embed static/*
var static embed.FS

type postData struct {
	Query     string                 `json:"query"`
	Operation string                 `json:"operation"`
	Variables map[string]interface{} `json:"variables"`
}

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

	authAddr := os.Getenv("AUTH_ADDR")
	if authAddr == "" {
		panic("No valid AUTH_ADDR received")
	}

	authAddrExt := os.Getenv("AUTH_ADDR_EXT")
	if authAddrExt == "" {
		panic("No valid AUTH_ADDR_EXT received")
	}

	caClient, err := ca.NewCAClient("api_service")
	if err != nil {
		panic(err)
	}

	certPool, err := caClient.CertPool(context.Background(), "api_service")
	if err != nil {
		panic(err)
	}

	crt, _, err := caClient.Certificate(context.Background(), "api_service", ca.Client)
	if err != nil {
		panic(err)
	}

	jwtKey, err := fetchJWTKey(authAddr)
	if err != nil {
		panic(err)
	}

	tlsConfig := &tls.Config{
		RootCAs:      certPool,
		Certificates: []tls.Certificate{crt},
	}
	userConn, err := grpc.Dial(userAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		panic(fmt.Errorf("error dialing %s, got error: %w", userAddr, err))
	}
	userClient := proto.NewUserServiceClient(userConn)

	clientConn, err := grpc.Dial(clientAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		panic(fmt.Errorf("error dialing %s, got error: %w", userAddr, err))
	}
	clientClient := proto.NewClientServiceClient(clientConn)

	schema, err := createSchema(userClient, clientClient)
	if err != nil {
		panic(err)
	}

	err = startServer(listenAddr, authAddr, authAddrExt, jwtKey, schema)
	if err != nil {
		log.Fatal(err)
	}
}

func fetchJWTKey(authAddr string) (*rsa.PublicKey, error) {
	// TODO ugly way to make sure the auth container is up and running
	tC := time.NewTimer(5 * time.Second)
	<-tC.C

	res, err := http.Get(authAddr + "/.well-known/cert")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(body)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert.PublicKey.(*rsa.PublicKey), nil
}

func startServer(listenAddr string, authAddr string, authAddrExt string, jwtKey *rsa.PublicKey, schema graphql.Schema) error {
	router := mux.NewRouter()

	httpServer := &http.Server{
		Addr:           listenAddr,
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")

		var redirect string
		if code == "" {
			redirect = fmt.Sprintf("%s/authorize?response_type=code&client_id=anything&redirect_uri=http://localhost:9097&scope=read&state=my_state&code_challenge_method=S256&code_challenge=Qn3Kywp0OiU4NK_AFzGPlmrcYJDJ13Abj_jdL08Ahg8=", authAddrExt)
		} else {
			tokenUrl := fmt.Sprintf("%s/token?grant_type=authorization_code&client_id=anything&redirect_uri=http://localhost:9097&code=%s&code_verifier=s256example", authAddr, code)
			token, err := fetchToken(tokenUrl)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			redirect = fmt.Sprintf("/graphiql?token=%s", token)
		}

		w.Header().Set("Location", redirect)
		w.WriteHeader(http.StatusFound)
	})

	router.HandleFunc("/graphiql", func(w http.ResponseWriter, r *http.Request) {
		f, err := static.Open("static/index.html")
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
	})

	router.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		var p postData
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			w.WriteHeader(400)
			return
		}
		result := graphql.Do(graphql.Params{
			Context:        r.Context(),
			Schema:         schema,
			RequestString:  p.Query,
			VariableValues: p.Variables,
			OperationName:  p.Operation,
		})
		if err := json.NewEncoder(w).Encode(result); err != nil {
			fmt.Printf("could not write result to response: %s", err)
		}
	})

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/graphql" {
				next.ServeHTTP(w, r)
				return
			}
			auth := r.Header.Get("Authorization")

			var token string
			if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
				token = r.URL.Query().Get("token")
				if token == "" {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			} else {
				token = strings.ReplaceAll(auth, "Bearer ", "")
			}
			log.Printf("Authorizing with %s", token)

			err := jws.Verify(token, jwtKey)
			if err != nil {
				log.Printf("Key verification failed: %v", err)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			set, err := jws.Decode(token)
			if err != nil {
				log.Printf("Error decoding token: %v", err)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			if set.Exp < time.Now().Unix() {
				log.Print("Token expired")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	})

	return httpServer.ListenAndServe()
}

func createSchema(userClient proto.UserServiceClient, clientClient proto.ClientServiceClient) (graphql.Schema, error) {
	userType := graphql.NewObject(
		graphql.ObjectConfig{
			Name: "User",
			Fields: graphql.Fields{
				"userId": &graphql.Field{
					Type: graphql.String,
				},
				"userName": &graphql.Field{
					Type: graphql.String,
				},
			},
		},
	)

	clientType := graphql.NewObject(
		graphql.ObjectConfig{
			Name: "Client",
			Fields: graphql.Fields{
				"id": &graphql.Field{
					Type: graphql.String,
				},
				"secret": &graphql.Field{
					Type: graphql.String,
				},
				"domain": &graphql.Field{
					Type: graphql.String,
				},
				"userID": &graphql.Field{
					Type: graphql.String,
				},
			},
		},
	)

	return graphql.NewSchema(graphql.SchemaConfig{
		Query: graphql.NewObject(
			graphql.ObjectConfig{
				Name: "Query",
				Fields: graphql.Fields{
					"user": &graphql.Field{
						Type: userType,
						Args: graphql.FieldConfigArgument{
							"id": &graphql.ArgumentConfig{
								Type: graphql.String,
							},
						},
						Resolve: func(p graphql.ResolveParams) (interface{}, error) {
							id, ok := p.Args["id"].(string)
							if ok {
								log.Printf("Fetching user with id %s", id)
								res, err := userClient.UserByID(context.Background(), &proto.UserByIdRequest{Id: id})
								if err != nil {
									return nil, err
								}
								return res.User, nil
							}
							return nil, errors.New("no id provided")
						},
					},
					"client": &graphql.Field{
						Type: clientType,
						Args: graphql.FieldConfigArgument{
							"id": &graphql.ArgumentConfig{
								Type: graphql.String,
							},
						},
						Resolve: func(p graphql.ResolveParams) (interface{}, error) {
							id, ok := p.Args["id"].(string)
							if ok {
								log.Printf("Fetching client with id %s", id)
								res, err := clientClient.ClientByID(context.Background(), &proto.ClientByIDRequest{Id: id})
								if err != nil {
									return nil, err
								}
								return res.Client, nil
							}
							return nil, errors.New("no id provided")
						},
					},
				},
			},
		),
	})
}

func fetchToken(tokenUrl string) (string, error) {
	resp, err := http.Get(tokenUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	type envelope struct {
		AccessToken string `json:"access_token"`
	}
	var e envelope
	err = json.Unmarshal(body, &e)
	if err != nil {
		return "", err
	}
	return e.AccessToken, nil
}
