package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"gitlab.jaztec.info/jaztec/microservice-example/ca"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"gitlab.jaztec.info/jaztec/microservice-example/auth"
)

//.well-known/jwks.json

func main() {
	clientAddr := os.Getenv("CLIENT_ADDR")
	if clientAddr == "" {
		panic("No valid CLIENT_ADDR received")
	}

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		panic("No valid LISTEN_ADDR received")
	}

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
	// client memory store
	clientStore, err := auth.NewStore(clientAddr)
	if err != nil {
		panic(err)
	}
	defer clientStore.Close()

	manager.MapClientStorage(clientStore)

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

	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			log.Print(fmt.Errorf("error handling token: %+v", err))
		}
	})

	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
