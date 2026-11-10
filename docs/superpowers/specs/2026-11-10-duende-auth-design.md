# Duende authentication for existing TeamCity users

## Intent and scope
Adapt JetBrains' TeamCity OIDC authentication plug-in so staff authenticate with
Duende IdentityServer and enter an existing TeamCity account by matching username.
Never create accounts. TeamCity retains control of permissions and group membership.

## Approaches
Considered a separate authentication plug-in and adapting the JetBrains OIDC
plug-in. The user selected the latter to reuse its TeamCity integration and OIDC
validation. Upstream baseline: 0237973408c70bc7f75c9cee10e2e44e072a196c.

## Proposed implementation
- Keep Java/Maven and the upstream TeamCity 2025.11 API target. Actual server
  compatibility must be checked when the installed version becomes available.
- Use authorization code flow with S256 PKCE, session-bound state and nonce,
  and existing signature, issuer, audience and expiry validation.
- Trust one configured Duende issuer. Default the configurable username claim to
  `preferred_username`; Duende must emit the administrator-controlled claim with
  the same value as the TeamCity username. Missing claims deny access.
- Match an existing account by username. For the first login, the trusted username
  is sufficient; remove the upstream requirement for matching verified emails.
  Record issuer and subject on successful linking. Later mismatches deny access
  rather than relink the account. Reject UserInfo subject mismatches before using
  supplementary claims.
- Remove account creation from this variant's authentication path and settings UI;
  legacy configuration enabling creation must not override this policy.
- Disable group synchronization in this variant so sign-in preserves TeamCity
  permissions. Preserve the built-in TeamCity login for administrative recovery.
- Supply an example `oidc-auth.json`, Duende confidential-client registration,
  claim-emission instructions and installation/build documentation. Use placeholders
  for issuer, public TeamCity URL and secret; no live credentials are required to build.
- Keep the upstream plug-in identity and paths for compatibility; this is a
  replacement build, not an additional module to install beside upstream.

## Validation and delivery
Add regression tests for existing-user success, unknown-user denial even with
legacy auto-create settings, subject/issuer mismatch, claim mismatch, and PKCE
authorization/token exchange. Run the Maven tests and package a deployable ZIP.
Live Duende/TeamCity sign-in remains unverified until an installation is available.

## Builder decisions and exclusions
The implementer may choose internal helper structure, dependency-compatible PKCE
utilities and test doubles. No deployment, group provisioning, new-user onboarding,
or migration of existing upstream subject bindings is in scope. Existing bindings
without issuer metadata must be handled explicitly and fail closed if ambiguous.

## Status
Approved by user: “Do it”. Implementation authorized.
