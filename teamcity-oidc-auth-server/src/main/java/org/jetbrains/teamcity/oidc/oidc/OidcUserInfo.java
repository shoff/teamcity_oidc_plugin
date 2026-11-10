package org.jetbrains.teamcity.oidc.oidc;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.HashMap;
import java.util.Map;

/**
 * UserInfo claims with their original JSON types. In particular, a numeric or
 * boolean username must never be coerced to a String that could select an account.
 */
public class OidcUserInfo {

    private final Map<String, Object> raw = new HashMap<>();

    @JsonAnySetter
    public void setRawClaim(String key, Object value) {
        raw.put(key, value);
    }

    public String getSub() { return stringClaim("sub"); }
    public String getEmail() { return stringClaim("email"); }
    public Boolean getEmailVerified() {
        Object value = raw.get("email_verified");
        return value instanceof Boolean ? (Boolean) value : null;
    }
    public String getName() { return stringClaim("name"); }
    public String getPreferredUsername() { return stringClaim("preferred_username"); }
    public String getGivenName() { return stringClaim("given_name"); }
    public String getFamilyName() { return stringClaim("family_name"); }

    @JsonIgnore
    public Map<String, Object> getRaw() { return raw; }

    private String stringClaim(String name) {
        Object value = raw.get(name);
        return value instanceof String ? (String) value : null;
    }
}
