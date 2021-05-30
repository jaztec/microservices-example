[![pipeline status](https://gitlab.jaztec.info/jaztec/microservice-example/badges/master/pipeline.svg)](https://gitlab.jaztec.info/jaztec/microservice-example/-/commits/master)
[![coverage report](https://gitlab.jaztec.info/jaztec/microservice-example/badges/master/coverage.svg)](https://gitlab.jaztec.info/jaztec/microservice-example/-/commits/master)

# Microservices example

This is an experimental from the ground up microservices example. It uses mTLS 
to communicate between the  different programs. 

The repo uses [`docker`](https://docs.docker.com/get-docker/) and 
[`docker-compose`](https://docs.docker.com/compose/install/). 

Pull the repository and run the following commands:

```bash
$ git clone https://github.com/jaztec/microservices-example.git 
$ cd microservices-example
$ docker-compose up --build
```
 
This should get you a running setup at `http://localhost:9097`. 
Going there takes you to a login page that is wired for the example. The 
credentials are simply `test` and `test`.

Alternatively you can use the client credentials grant, that works with any
`client_id` and `client_secret` set to `42`:

`http://localhost:9096/token?grant_type=client_credentials&client_id=anything&client_secret=42&scope=read`

This example is not persistent. Taking it down will clear all certificates as will
restarting a single application.
