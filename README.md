# Api-Platform 3.1 + Symfony 6.3 + OAuth2 with Keycloak Provider

## Install
- Clone the project
- `composer install`
- `cp .env .env.local`
- Change the Keycloak variables and database
- `symfony doctrine:database:create`
- `symfony doctrine:migration:migrate`
- `symfony server:start`

Go to https://localhost:8000/api