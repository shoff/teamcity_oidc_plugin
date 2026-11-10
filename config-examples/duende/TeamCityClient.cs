// Merge this client into your existing Duende configuration/store.
// Reference snippet, not a standalone IdentityServer application.
using System;
using Duende.IdentityServer.Models;

public static class TeamCityClient
{
    public static Client Create(string publicTeamCityUrl, string clientSecret)
    {
        if (string.IsNullOrWhiteSpace(clientSecret))
            throw new ArgumentException("A client secret is required", nameof(clientSecret));

        return new Client
        {
            ClientId = "teamcity",
            ClientName = "TeamCity",
            AllowedGrantTypes = GrantTypes.Code,
            RequireClientSecret = true,
            ClientSecrets = { new Secret(clientSecret.Sha256()) },
            RequirePkce = true,
            AllowPlainTextPkce = false,
            RedirectUris = { publicTeamCityUrl.TrimEnd('/') + "/app/oidc/callback" },
            AllowedScopes = { "openid", "profile", "email" },
            // Include preferred_username in the ID token when emitted by your profile service.
            AlwaysIncludeUserClaimsInIdToken = true,
            AllowOfflineAccess = false
        };
    }
}
