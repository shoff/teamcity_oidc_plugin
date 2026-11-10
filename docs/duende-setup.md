# Duende IdentityServer setup

This replacement build of JetBrains' OIDC plug-in signs users into existing
TeamCity accounts. It never creates accounts or changes group membership, even
when an older configuration enables those features. It targets TeamCity 2025.11
APIs; check the installed server version before deployment. Use the Java runtime
required by that TeamCity release.

## Register TeamCity in Duende

Use [TeamCityClient.cs](../config-examples/duende/TeamCityClient.cs) as a reference
for your existing client store. Pass the public HTTPS TeamCity root URL, including
any context path, and a generated secret from your secret store. Store its SHA-256
hash in Duende and the original value in TeamCity's plug-in configuration.

The client uses authorization code flow, a confidential-client secret, and S256
PKCE. The redirect URI is exactly:

```
https://teamcity.example.com/app/oidc/callback
```

If TeamCity runs under `/teamcity`, include that prefix. Configure TeamCity's
server URL to its public HTTPS URL so the callback matches behind a reverse proxy.
Browser and TeamCity server must both be able to reach the issuer; TeamCity must
trust its TLS certificate. Use the issuer exactly as advertised by Duende.

Ensure `openid`, `profile`, and `email` identity resources are registered in your
existing Duende configuration (`IdentityResources.OpenId`, `.Profile`, `.Email`).
Your profile service must issue `preferred_username` containing the exact existing
TeamCity username. The standard profile resource permits this claim but does not
populate it automatically. Emit it in the ID token or the UserInfo response.
The `AlwaysIncludeUserClaimsInIdToken` example setting puts emitted profile claims
in the ID token; it does not invent missing claims.

The username claim must be controlled by your organization. A user who can choose
another employee's TeamCity username could otherwise link to that employee's
account on first sign-in. Do not use an editable display name. If your issued
claim has another name, change `usernameClaim.claimName` in the plug-in settings.
Username values must be nonblank strings. Matching uses TeamCity's account lookup
semantics; the plug-in does not trim, lowercase, or otherwise rewrite usernames.

## Configure and install the plug-in

1. Build from the repository root with `mvn clean package`. The ZIP is
   `target/oidc-auth.zip`. To target another SDK explicitly, use
   `mvn -Dteamcity-version=<version> clean package` and verify against that server.
2. Preserve a working built-in TeamCity administrator login. Back up the current
   plug-in and settings if replacing the upstream build. This build has the same
   plug-in identity and routes: install it as a replacement, never alongside it.
3. Upload the ZIP in **Administration → Plugins**, following TeamCity's restart
   instructions.
4. Copy [the configuration example](../config-examples/duende/oidc-auth.example.json)
   to `<TeamCity Data Directory>/config/oidc-auth.json`. Replace the issuer and
   secret placeholders. Restrict file access to the TeamCity service account.
   Alternatively use the plug-in's administration settings, which persist the
   secret using TeamCity's encryption support.
5. In **Administration → Authentication**, add the **OpenID Connect** module.
   Use the IdentityServer login button to test with an existing account.

## Account linking and recovery

On first successful sign-in the trusted username selects an existing account.
The plug-in records `oidc.issuer` and `oidc.sub` on that account. Subsequent sign-ins
must match both. A different issuer or subject is rejected even if the username
and email match. There is no email fallback or automatic relinking.

Legacy upstream accounts with `oidc.sub` but no issuer are rejected. For migration,
an administrator must verify the identity through an independent channel and set
the correct issuer binding, or deliberately clear both binding attributes through
approved TeamCity administration tooling before relinking. Partial bindings also
deny access. This build does not provide a bulk migration or reset endpoint.

When changing identity providers or recreating a Duende user, plan that explicit
administrative relinking step. Do not reuse departed users' TeamCity accounts.

## Deployment boundary

The initial account-linking lock is local to one TeamCity JVM. Use this build on
one authentication-serving TeamCity node. Concurrent first-time linking across
multiple nodes has not been validated and would need a distributed atomic binding
operation before this build could claim that support.

## Acceptance checks on your installation

- An existing username signs in and retains its TeamCity permissions.
- A Duende-only username is denied and no TeamCity account appears.
- A missing username claim or changed bound subject/issuer is denied.
- Duende rejects authorization requests without PKCE; this plug-in still signs in.
- Built-in administrator login remains usable.

Automated tests use mocks and local HTTP fixtures. A live TeamCity/Duende sign-in
must still be tested in your environment. The C# snippet is reference configuration
and is not a separately compiled or deployed identity server.

## References

- [Upstream JetBrains plug-in](https://github.com/JetBrains/teamcity-oidc-auth-plugin)
- [Duende client configuration](https://docs.duendesoftware.com/identityserver/reference/v8/models/client/)
- [Duende identity resources](https://docs.duendesoftware.com/identityserver/fundamentals/resources/identity/)
