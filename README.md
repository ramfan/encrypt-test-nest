
## Description

Backend for encrypt/decrypt data. This project have role just only an example. This project show how we can files and
other data encrypt/decrypt with RSA and AES-CBC algorithms.

## Installation

```bash
$ yarn install
```

## Folder preparing
We need make two directories for next work
```bash
$  mkdir ./files
```
```bash
$  mkdir ./keys
```
## Key generation
Generated keys need place on directory `/keys` in root project directory
### Generation private key with name `private.pem` with size `4096` bit or other available size
```bash
$  openssl genrsa -out private.pem 4096
```
### Generation public key with name `pub.pem` from `private.pem`
```bash
$  openssl rsa -in private.pem -pubout -out pub.pem
```
### Generation `pkcs8` format from `private.pem`
```bash
$  openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private.pem -out pkcs8.key
```


## Running the app

```bash
# development
$ yarn run start

# watch mode
$ yarn run start:dev

# production mode
$ yarn run start:prod
```

## Test

```bash
# unit tests
$ yarn run test

# e2e tests
$ yarn run test:e2e

# test coverage
$ yarn run test:cov
```

## Support


## License

Nest is [MIT licensed](LICENSE).
