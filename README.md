# paymenthub-ee-auth

The authentication and user-management service of Payment Hub EE: it issues the tokens every other
Payment Hub EE component checks, and it owns the users, roles and permissions behind them.

[![License](https://img.shields.io/badge/License-MPL--2.0-blue.svg)](LICENSE)

## What it does

- Issues access and refresh tokens at `POST /oauth/token`. Tokens are RSA-signed JWTs, valid for
  10 minutes; a refresh token lasts 12 hours.
- Publishes the public half of the signing key at `GET /oauth/token_key`, so other services can
  verify a token without calling back here, and answers `POST /oauth/check_token` for callers that
  would rather ask.
- Manages users, roles and permissions under `/api/v1` — `/users`, `/roles`, `/permissions` and the
  calls that attach roles to a user or permissions to a role.
- Serves read-only views of workflow data under the same prefix: `/transactions`,
  `/transaction/{workflowInstanceKey}`, `/tasks` and `/variables`.
- Keeps each tenant's data in its own database, and runs the Flyway migrations for every tenant it
  finds at startup.

## How it fits into Payment Hub EE

Every request that reaches Payment Hub EE from outside arrives with a bearer token, and this is the
service that issued it. The web consoles sign in here; the other components verify the token with
the public key published at `/oauth/token_key` rather than calling this service on each request, so
it is not on the hot path of a payment. It was previously called `ph-ee-identity-provider`.

Payment Hub EE is multi-tenant, and this service is where that starts. Every call except
`/oauth/token_key` has to say which tenant it is for, in the `Platform-TenantId` header or a
`tenantIdentifier` query parameter. A request with no tenant is rejected before authentication
runs, because the tenant decides which database the user is looked up in.

## Tech stack

- Java 21
- Spring Boot 3.4 (Web, Security, OAuth2 resource server, Cache, Data JPA)
- EclipseLink as the JPA provider, not Hibernate
- MySQL, with one datasource per tenant and Flyway for migrations
- Jakarta EE 10
- Gradle build; versions come from `paymenthub-ee-bom`

## Build and run

    ./gradlew clean build          # compiles and runs the tests
    ./gradlew bootRun              # runs the service locally
    docker build -t paymenthub-ee-auth .

The service listens on port 5000. It needs a MySQL instance holding a `tenants` schema that lists
the tenants and, for each one, how to reach its database. The defaults in
`src/main/resources/application.properties` point at a host named `operations-mysql`, which is the
service name inside a Payment Hub EE deployment; override them for a local run:

    fineract.datasource.core.host       # MySQL host, default operations-mysql
    fineract.datasource.core.port       # default 3306
    fineract.datasource.core.schema     # schema holding the tenant list, default tenants
    fineract.datasource.core.username
    fineract.datasource.core.password

Spring's relaxed binding means each of these can also be set as an environment variable, for
example `FINERACT_DATASOURCE_CORE_HOST`.

Tokens are signed with the RSA key pair in `src/main/resources` (`jwt.pem` and `jwt_pub.pem`).
Those files are a development key pair, committed so the service starts out of the box. **A real
deployment must supply its own**, because anything holding the private key can mint a token that
every other component will accept.

## Branches

- `dev` is the active development branch — all PRs should target `dev`.
- `main` holds released versions.

## Contributing

See [contributing.md](contributing.md), our [Code of Conduct](CODE_OF_CONDUCT.md) and the [security policy](security.md).
