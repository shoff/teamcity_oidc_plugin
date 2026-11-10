# TeamCity authentication with Duende IdentityServer

A replacement build of the [JetBrains OIDC authentication plug-in](https://github.com/JetBrains/teamcity-oidc-auth-plugin), adapted for existing TeamCity users.

- Sign in through Duende using authorization code flow with S256 PKCE.
- Match a configurable username claim (`preferred_username` by default).
- Never create TeamCity accounts or modify group membership.
- Bind an account to issuer and subject after first sign-in; reject identity changes.
- Validate ID tokens and require matching UserInfo subjects.

See the [Duende installation and configuration guide](docs/duende-setup.md),
[TeamCity configuration example](config-examples/duende/oidc-auth.example.json), and
[Duende client registration snippet](config-examples/duende/TeamCityClient.cs).

## Download

The verified installable ZIP is [artifacts/oidc-auth.zip](artifacts/oidc-auth.zip).
Its SHA-256 checksum is alongside it. Follow the setup guide before installing.

## Build

Requires Maven and a JDK compatible with the selected TeamCity SDK (verified here
using JDK 21). The API target is TeamCity 2025.11; the deployed server must be
compatible with that API. Use TeamCity's supported runtime on the server.

```bash
mvn clean package
```

Install `target/oidc-auth.zip`. This build retains the upstream plug-in identity;
replace the upstream installation rather than installing both builds.

```bash
mvn -pl teamcity-oidc-auth-server test
```

Tests use JUnit, Mockito and local WireMock fixtures. Live TeamCity/Duende sign-in
has not been verified in this workspace. No service credentials are included.

## Upstream

Based on JetBrains/teamcity-oidc-auth-plugin commit
`0237973408c70bc7f75c9cee10e2e44e072a196c`. Upstream identifies its license as
Apache 2.0. This adaptation is not an official JetBrains or Duende release.
