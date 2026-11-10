# Duende Authentication Implementation Plan

> Execute inline with superpowers:executing-plans; user authorized implementation.

**Goal:** Build an installable Duende OIDC plug-in for existing TeamCity accounts.
**Architecture:** Adapt the upstream Java authentication module and preserve its
TeamCity extension integration. Bind matched accounts to issuer and subject.
**Tech Stack:** Java 8 source, Maven, TeamCity 2025.11 APIs, JUnit 4, Mockito, WireMock.
**Spec:** ../specs/2026-11-10-duende-auth-design.md (approved by user).

## Global constraints
No account creation or group synchronization. Configurable trusted username claim,
default preferred_username. Authorization code with S256 PKCE. No live deployment.

## Review focus
Missing nonce/verifier; changed issuer/subject; legacy configuration; standard
UserInfo fields absent from its raw claim map; malformed username claim values.

### Task 1: Account policy
- [x] Replace upstream provisioning/group-sync tests with existing-account policy
  assertions; add issuer/subject, missing username and UserInfo regression cases.
- [x] Run tests and observe failures before changing production code.
- [x] Update OidcAuthenticationScheme account lookup, binding, and claim handling;
  update OidcPluginSettings defaults and fixed policy getters; remove provisioning
  and group-sync settings controls. Legacy setters remain for JSON compatibility.
- [x] Run authentication/settings tests; expect no failures.

### Task 2: PKCE
- [x] Add RFC 7636 challenge vector, verifier single-use, authorization URL and
  token form assertions in state, login, client and authentication tests.
- [x] Observe failures; implement generateCodeChallenge(HttpSession),
  consumeCodeVerifier(HttpSession), and static codeChallenge(String) in
  OidcStateManager. Add required sixth verifier argument to token exchange.
- [x] Require nonce/verifier before code exchange; send S256 challenge on login.
- [x] Run state/login/client/auth tests; expect no failures.

### Task 3: Delivery
- [x] Add examples/duende client registration and oidc-auth.json plus setup guide.
- [x] Identify replacement build clearly and document account-binding recovery.
- [x] Run mvn package, inspect ZIP and review the complete diff. Supply artifact
  and disclose that live Duende/TeamCity authentication was not exercised.
