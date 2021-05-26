package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
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

	err = startServer(listenAddr, jwtKey, schema)
	if err != nil {
		log.Fatal(err)
	}
}

func fetchJWTKey(authAddr string) (*rsa.PublicKey, error) {
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

func startServer(listenAddr string, jwtKey *rsa.PublicKey, schema graphql.Schema) error {
	router := mux.NewRouter()

	httpServer := &http.Server{
		Addr:           listenAddr,
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	router.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		result := graphql.Do(graphql.Params{
			Schema:        schema,
			RequestString: r.URL.Query().Get("query"),
		})
		json.NewEncoder(w).Encode(result)
	})

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")

			if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			token := strings.ReplaceAll(auth, "Bearer ", "")
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
