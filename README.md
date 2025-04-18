# Envoy Plugin for Thrift Annotation based auth

## TODO

- [x] add "thrift" file
- [x] create main service based on thrift file
- [x] add simple client to call service
- [x] route the client / service traffic through Envoy
- [x] create mock auth server with FastAPI
- [x] authenticate based on a JWT in the auth header
  - [x] get the auth token in the client and add it as a header
  - [x] get the public key in the configure hook 
  - [x] validate the JWT based on the token 
- [x] authorize based on a scope in the token
  - [x] parse the service name from the envoy config
  - [x] add the required scopes to the thrift annotation
  - [x] add the scope to the token in auth service
  - [x] parse the method from the thrift request body
  - [x] parse thrift in auth service to get required scopes
  - [x] return the required scopes for service/endpoint from auth service
  - [x] validate scopes in the envoy plugin

### Stretch Goals
- [x] Read only partial body when parsing thrift method
- [ ] Move public token fetch to a singleton service

## Running the plugin

If this your first time working with this repo, follow the install instructions at [Setup.md](./SETUP.md)

### Building

```sh
$ cargo build --target wasm32-wasip1 --release
```

### Using in Envoy

This example can be run with [`docker compose`](https://docs.docker.com/compose/install/)
and has a matching Envoy configuration.

```sh
$ cd /hack
$ docker compose up
```
