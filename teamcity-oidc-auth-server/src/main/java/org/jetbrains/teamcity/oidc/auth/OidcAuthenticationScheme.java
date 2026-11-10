package org.jetbrains.teamcity.oidc.auth;

import jetbrains.buildServer.RootUrlHolder;
import jetbrains.buildServer.controllers.interceptors.auth.HttpAuthenticationResult;
import jetbrains.buildServer.controllers.interceptors.auth.HttpAuthenticationSchemeAdapter;
import jetbrains.buildServer.controllers.interceptors.auth.util.HttpAuthUtil;
import jetbrains.buildServer.groups.UserGroupManager;
import jetbrains.buildServer.log.LogUtil;
import jetbrains.buildServer.log.Loggers;
import jetbrains.buildServer.serverSide.auth.LoginConfiguration;
import jetbrains.buildServer.serverSide.auth.ServerPrincipal;
import jetbrains.buildServer.users.SUser;
import jetbrains.buildServer.users.UserModelEx;
import jetbrains.buildServer.users.impl.UserEx;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.teamcity.oidc.OidcConstants;
import org.jetbrains.teamcity.oidc.config.OidcClaimMappingSettings;
import org.jetbrains.teamcity.oidc.config.OidcPluginSettings;
import org.jetbrains.teamcity.oidc.config.OidcPluginSettingsStorage;
import org.jetbrains.teamcity.oidc.oidc.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.*;

public class OidcAuthenticationScheme extends HttpAuthenticationSchemeAdapter {

    private final OidcPluginSettingsStorage settingsStorage;
    private final OidcClient oidcClient;
    private final OidcIdTokenValidator tokenValidator;
    private final OidcStateManager stateManager;
    private final UserModelEx userModel;
    private final RootUrlHolder rootUrlHolder;

    public OidcAuthenticationScheme(
            @NotNull LoginConfiguration loginConfiguration,
            @NotNull OidcPluginSettingsStorage settingsStorage,
            @NotNull OidcClient oidcClient,
            @NotNull OidcIdTokenValidator tokenValidator,
            @NotNull OidcStateManager stateManager,
            @NotNull UserModelEx userModel,
            @NotNull UserGroupManager userGroupManager,
            @NotNull RootUrlHolder rootUrlHolder) {
        this.settingsStorage = settingsStorage;
        this.oidcClient = oidcClient;
        this.tokenValidator = tokenValidator;
        this.stateManager = stateManager;
        this.userModel = userModel;
        this.rootUrlHolder = rootUrlHolder;

        loginConfiguration.registerAuthModuleType(this);
    }

    @NotNull
    @Override
    protected String doGetName() {
        return OidcConstants.AUTH_SCHEME_NAME;
    }

    @NotNull
    @Override
    public String getDescription() {
        return OidcConstants.AUTH_SCHEME_DESCRIPTION;
    }

    @Override
    public boolean isMultipleInstancesAllowed() {
        return false;
    }

    @Override
    public String getEditPropertiesJspFilePath() {
        return OidcConstants.ADMIN_SETTINGS_PATH;
    }

    public boolean isConfigured() {
        OidcPluginSettings s = settingsStorage.getSettings();
        return s.settingsAreConfigured();
    }

    @NotNull
    @Override
    public String describeProperties(@NotNull Map<String, String> properties) {
        String issuerUrl = settingsStorage.getSettings().getIssuerUrl();
        return "Issuer URL: " + (issuerUrl == null ? "<not configured>" : issuerUrl);
    }

    /**
     * Called by TC's auth interceptor for requests that require authentication.
     * Returns {@code notApplicable()} for all requests that are not the OIDC callback
     * carrying a {@code code} parameter.
     */
    @NotNull
    @Override
    public HttpAuthenticationResult processAuthenticationRequest(
            @NotNull HttpServletRequest request,
            @NotNull HttpServletResponse response,
            @NotNull Map<String, String> properties) throws IOException {

        String code = request.getParameter("code");
        if (code == null || !request.getRequestURI().contains(OidcConstants.CALLBACK_PATH)) {
            return HttpAuthenticationResult.notApplicable();
        }

        Loggers.AUTH.debug("OIDC: processing callback for " + request.getRequestURI());

        try {
            return doProcessCallback(request, code);
        } catch (OidcAuthException e) {
            return fail(request, response, e.getMessage());
        } catch (OidcClientException e) {
            Loggers.AUTH.error("OIDC: IdP communication failure during callback", e);
            return fail(request, response, "Authentication failed: could not communicate with identity provider");
        } catch (Exception e) {
            Loggers.AUTH.error("OIDC: unexpected error during callback processing", e);
            return fail(request, response, "Authentication failed: " + e.getMessage());
        }
    }

    // ---- Core callback logic -----------------------------------------------

    @NotNull
    private HttpAuthenticationResult doProcessCallback(
            @NotNull HttpServletRequest request,
            @NotNull String code) throws OidcAuthException, OidcClientException {

        OidcPluginSettings settings = settingsStorage.getSettings();

        // 1. Validate state (anti-CSRF)
        HttpSession session = request.getSession(false);
        if (session == null) {
            throw new OidcAuthException("No session found — state cannot be validated");
        }
        String stateParam = request.getParameter("state");
        if (!stateManager.validateAndConsumeState(session, stateParam)) {
            throw new OidcAuthException("State parameter mismatch — possible CSRF attack");
        }

        String nonce = stateManager.consumeNonce(session);
        String codeVerifier = stateManager.consumeCodeVerifier(session);
        if (nonce == null || nonce.isEmpty() || codeVerifier == null || codeVerifier.isEmpty()) {
            throw new OidcAuthException("Login transaction is missing nonce or PKCE verifier");
        }

        // 2. Resolve token endpoint
        String tokenEndpoint = resolveTokenEndpoint(settings);

        // 3. Build redirect URI (must match what was sent to IdP)
        String redirectUri = getCallbackUrl(settings);

        // 4. Exchange code for tokens
        OidcTokenResponse tokenResponse = oidcClient.exchangeCodeForTokens(
                tokenEndpoint, code, redirectUri, settings.getClientId(), settings.getClientSecret(), codeVerifier);

        String rawIdToken = tokenResponse.getIdToken();
        if (rawIdToken == null || rawIdToken.isEmpty()) {
            throw new OidcAuthException("Token endpoint response did not include an id_token");
        }

        // 5. Validate ID token
        String jwksUri = resolveJwksUri(settings);
        OidcIdTokenClaims idTokenClaims = tokenValidator.validateAndDecode(
                rawIdToken, jwksUri, settings.getIssuerUrl(),
                settings.getClientId(), nonce, settings.getTokenClockSkewSeconds());

        if (idTokenClaims.getSub() == null || idTokenClaims.getSub().trim().isEmpty()) {
            throw new OidcAuthException("ID token missing subject");
        }

        // 6. Optionally fetch userinfo for supplemental claims
        OidcUserInfo userInfo = null;
        String userInfoEndpoint = resolveUserInfoEndpoint(settings);
        if (userInfoEndpoint != null && tokenResponse.getAccessToken() != null) {
            try {
                userInfo = oidcClient.fetchUserInfo(userInfoEndpoint, tokenResponse.getAccessToken());
            } catch (OidcClientException e) {
                Loggers.AUTH.warn("OIDC: failed to fetch userinfo (continuing without it): " + e.getMessage());
            }
        }

        if (userInfo != null && !idTokenClaims.getSub().equals(userInfo.getSub())) {
            throw new OidcAuthException("UserInfo subject does not match ID token");
        }

        // 7. Resolve TeamCity username
        String username = resolveUsername(settings, idTokenClaims, userInfo);
        if (username == null || username.trim().isEmpty()) {
            throw new OidcAuthException("Could not resolve a username from token claims");
        }

        // 8. Apply email domain allowlist
        String email = resolveClaim(settings.getEmailClaim(), idTokenClaims, userInfo);
        if (!settings.getAllowedEmailDomains().isEmpty()) {
            if (email == null) {
                throw new OidcAuthException("Email claim is required when an email allowlist is configured");
            }
            checkEmailDomain(email, settings.getAllowedEmailDomains());
        }

        String sub = idTokenClaims.getSub();

        // Match only existing users. Serialize binding checks and writes within this
        // server process so competing first callbacks cannot overwrite one another.
        SUser user;
        synchronized (userModel) {
            user = userModel.findUserAccount(null, username);
            if (user == null) {
                throw new OidcAuthException("No matching TeamCity account; contact your administrator");
            }
            UserEx account = (UserEx) user;
            String existingSub = account.getAttribute(OidcConstants.OIDC_SUB_ATTRIBUTE);
            String existingIssuer = account.getAttribute(OidcConstants.OIDC_ISSUER_ATTRIBUTE);
            if (existingSub != null || existingIssuer != null) {
                if (!sub.equals(existingSub) || !settings.getIssuerUrl().equals(existingIssuer)) {
                    throw new OidcAuthException("TeamCity account is linked to a different or incomplete OIDC identity");
                }
            } else {
                account.setAttribute(OidcConstants.OIDC_ISSUER_ATTRIBUTE, settings.getIssuerUrl());
                account.setAttribute(OidcConstants.OIDC_SUB_ATTRIBUTE, sub);
            }
        }

        // Store access token and user ID in session to support per-request token introspection
        // (OidcTokenIntrospectionInterceptor). Only stored when an access token was issued.
        if (tokenResponse.getAccessToken() != null) {
            session.setAttribute(OidcConstants.SESSION_ACCESS_TOKEN, tokenResponse.getAccessToken());
            session.setAttribute(OidcConstants.SESSION_USER_ID, user.getId());
        }

        Loggers.AUTH.info("OIDC: authenticated user " + LogUtil.describe(user) + " using the claims: (sub='" + sub + "', email='" + email + "')");
        String redirectUrl = getPostLoginRedirect(session, request);
        return HttpAuthenticationResult.authenticated(
                new ServerPrincipal(user.getRealm(), user.getUsername(), null,
                        false, new HashMap<>()),
                true).withRedirect(redirectUrl);
    }

    // ---- Helpers -----------------------------------------------------------

    @NotNull
    private String resolveTokenEndpoint(@NotNull OidcPluginSettings settings) throws OidcClientException {
        if (!settings.isDiscoveryEnabled() && settings.getTokenEndpoint() != null) {
            return settings.getTokenEndpoint();
        }
        return oidcClient.fetchDiscoveryDocument(settings.getIssuerUrl()).getTokenEndpoint();
    }

    @NotNull
    private String resolveJwksUri(@NotNull OidcPluginSettings settings) throws OidcClientException {
        if (!settings.isDiscoveryEnabled() && settings.getJwksUri() != null) {
            return settings.getJwksUri();
        }
        return oidcClient.fetchDiscoveryDocument(settings.getIssuerUrl()).getJwksUri();
    }

    @Nullable
    private String resolveUserInfoEndpoint(@NotNull OidcPluginSettings settings) throws OidcClientException {
        if (!settings.isDiscoveryEnabled()) {
            return settings.getUserInfoEndpoint();
        }
        return oidcClient.fetchDiscoveryDocument(settings.getIssuerUrl()).getUserInfoEndpoint();
    }

    @NotNull
    public String getCallbackUrl(@NotNull OidcPluginSettings settings) {
        String base = rootUrlHolder.getRootUrl();

        // Strip trailing slash to avoid double-slash
        if (base.endsWith("/")) base = base.substring(0, base.length() - 1);
        return base + OidcConstants.CALLBACK_PATH;
    }

    @Nullable
    private String resolveUsername(@NotNull OidcPluginSettings settings,
                                   @NotNull OidcIdTokenClaims claims,
                                   @Nullable OidcUserInfo userInfo) {
        return resolveClaim(settings.getUsernameClaim(), claims, userInfo);
    }

    @Nullable
    private String resolveClaim(@NotNull OidcClaimMappingSettings mapping,
                                @NotNull OidcIdTokenClaims claims,
                                @Nullable OidcUserInfo userInfo) {
        switch (mapping.getMappingType()) {
            case SUB:
                return claims.getSub();
            case CLAIM:
                String claimName = mapping.getClaimName();
                if (claimName == null || claimName.isEmpty()) return null;
                // Try ID token first
                Object value = claims.getRaw().get(claimName);
                if (value != null) return value instanceof String ? (String) value : null;
                // Fall back to userinfo
                if (userInfo != null) {
                    Object uiValue = userInfo.getRaw().get(claimName);
                    if (uiValue instanceof String) return (String) uiValue;
                }
                return null;
            case NONE:
            default:
                return null;
        }
    }

    private void checkEmailDomain(@NotNull String email, @NotNull List<String> allowedDomains) throws OidcAuthException {
        int atIdx = email.lastIndexOf('@');
        if (atIdx < 0) throw new OidcAuthException("Email '" + email + "' is not valid");
        String domain = email.substring(atIdx + 1).toLowerCase(Locale.ROOT);
        boolean allowed = allowedDomains.stream()
                .anyMatch(d -> d.toLowerCase(Locale.ROOT).equals(domain));
        if (!allowed) {
            throw new OidcAuthException("Email domain '" + domain + "' is not in the allowed domains list");
        }
    }

    @NotNull
    private String getPostLoginRedirect(@NotNull HttpSession session, @NotNull HttpServletRequest request) {
        Object stored = session.getAttribute(OidcConstants.SESSION_REDIRECT_URL);
        if (stored instanceof String && !((String) stored).isEmpty()) {
            session.removeAttribute(OidcConstants.SESSION_REDIRECT_URL);
            return (String) stored;
        }
        Object urlKey = session.getAttribute("URL_KEY");
        if (urlKey instanceof String && !((String) urlKey).isEmpty()) {
            session.removeAttribute("URL_KEY");
            return (String) urlKey;
        }
        return request.getContextPath() + "/";
    }

    @NotNull
    private HttpAuthenticationResult fail(@NotNull HttpServletRequest request,
                                          @NotNull HttpServletResponse response,
                                          @NotNull String reason) throws IOException {
        Loggers.AUTH.warn("OIDC: authentication failed — " + reason);
        HttpAuthUtil.setUnauthenticatedReason(request, reason);
        String loginPage = request.getContextPath() + "/login.html?authError="
                + URLEncoder.encode(reason, "UTF-8");
        response.sendRedirect(loginPage);
        return HttpAuthenticationResult.unauthenticated();
    }
}
