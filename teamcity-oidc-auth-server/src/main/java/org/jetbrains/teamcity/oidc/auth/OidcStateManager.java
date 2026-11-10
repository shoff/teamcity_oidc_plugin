package org.jetbrains.teamcity.oidc.auth;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.teamcity.oidc.OidcConstants;

import javax.servlet.http.HttpSession;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Generates and validates per-request state tokens and nonces stored in the HTTP session.
 * Both values are consumed (removed from session) on first use to prevent replay.
 */
public class OidcStateManager {

    private static final SecureRandom RANDOM = new SecureRandom();

    /** Generates a secure random state value, stores it in the session, and returns it. */
    @NotNull
    public String generateState(@NotNull HttpSession session) {
        String state = randomToken();
        session.setAttribute(OidcConstants.SESSION_STATE, state);
        return state;
    }

    /**
     * Validates that the given state matches what is stored in the session.
     * Removes the stored value from the session (single-use).
     *
     * @return true if the state matches, false otherwise
     */
    public boolean validateAndConsumeState(@NotNull HttpSession session, @Nullable String state) {
        Object stored = session.getAttribute(OidcConstants.SESSION_STATE);
        session.removeAttribute(OidcConstants.SESSION_STATE);
        return stored != null && stored.equals(state);
    }

    /** Generates a secure random nonce, stores it in the session, and returns it. */
    @NotNull
    public String generateNonce(@NotNull HttpSession session) {
        String nonce = randomToken();
        session.setAttribute(OidcConstants.SESSION_NONCE, nonce);
        return nonce;
    }

    /**
     * Returns the nonce stored in the session and removes it (single-use).
     *
     * @return the nonce, or null if none was stored
     */
    @Nullable
    public String consumeNonce(@NotNull HttpSession session) {
        Object nonce = session.getAttribute(OidcConstants.SESSION_NONCE);
        session.removeAttribute(OidcConstants.SESSION_NONCE);
        return nonce != null ? nonce.toString() : null;
    }

    /** Store a 256-bit verifier in this session and return its S256 challenge. */
    @NotNull
    public String generateCodeChallenge(@NotNull HttpSession session) {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        session.setAttribute(OidcConstants.SESSION_CODE_VERIFIER, verifier);
        return codeChallenge(verifier);
    }

    @Nullable
    public String consumeCodeVerifier(@NotNull HttpSession session) {
        Object verifier = session.getAttribute(OidcConstants.SESSION_CODE_VERIFIER);
        session.removeAttribute(OidcConstants.SESSION_CODE_VERIFIER);
        return verifier instanceof String ? (String) verifier : null;
    }

    @NotNull
    public static String codeChallenge(@NotNull String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", e);
        }
    }

    private static String randomToken() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
