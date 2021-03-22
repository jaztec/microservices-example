# Microservices example

This is an experimental ground-up microservices example. It uses mTLS 
to communicate between the  different programs. 

The repo uses [`docker`](https://docs.docker.com/get-docker/) and 
[`docker-compose`](https://docs.docker.com/compose/install/). 

Pull the repository and run the following commands from the project 
directory:

```bash
$ docker-compose up --build
```
 
This should get you a running cloud behind `http://localhost:9096`. 
Going there takes you to a login page that is wired for the example. The 
credentials are simply `test` and `test`.

Alternatively you can use the client credentials grant, that works with any
`client_id` and `client_secret` as `42`:

`http://localhost:9096/token?grant_type=client_credentials&client_id=anything&client_secret=42&scope=read`

