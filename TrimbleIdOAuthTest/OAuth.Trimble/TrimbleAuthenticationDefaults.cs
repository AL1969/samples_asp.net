
using Microsoft.AspNetCore.Builder;

namespace AspNet.Security.OAuth.Trimble {
    /// <summary>
    /// Default values used by the Trimble authentication middleware.
    /// </summary>
    public static class TrimbleAuthenticationDefaults {
        /// <summary>
        /// Default value for <see cref="AuthenticationOptions.AuthenticationScheme"/>.
        /// </summary>
        public const string AuthenticationScheme = "Trimble";

        /*
        app.UseOAuthAuthentication(new OAuthOptions
        {
            AuthenticationScheme = "TID-AccessToken",
            DisplayName = "TID-AccessToken",
            ClientId = Configuration["Authentication:TrimbleID:ClientId"],
            ClientSecret = Configuration["Authentication:TrimbleID:ClientSecret"],
            CallbackPath = new PathString("/auth_trimbleid/oauth_after.html"),
            AuthorizationEndpoint = "https://identity-stg.trimble.com/i/oauth2/authorize",
            TokenEndpoint = "https://identity-stg.trimble.com/i/oauth2/token",
            UserInformationEndpoint = "https://identity-stg.trimble.com/userinfo?schema=openid",
            SaveTokens = false,
            Scope = { "openid" },
            // Retrieving user information is unique to each provider.
            Events = new OAuthEvents
            {
                OnCreatingTicket = async context => { await CreatingTrimbleIdAuthTicket(context); }
            }
        });
        */

        /// <summary>
        /// Default value for <see cref="RemoteAuthenticationOptions.DisplayName"/>.
        /// </summary>
        public const string DisplayName = "Trimble Identity";

        /// <summary>
        /// Default value for <see cref="AuthenticationOptions.ClaimsIssuer"/>.
        /// </summary>
        public const string Issuer = "Trimble";

        /// <summary>
        /// Default value for <see cref="RemoteAuthenticationOptions.CallbackPath"/>.
        /// </summary>
        //public const string CallbackPath = "/signin-Trimble";
        public const string CallbackPath = "/auth_trimbleid/oauth_after.html";

        /// <summary>
        /// Default value for <see cref="OAuthOptions.AuthorizationEndpoint"/>.
        /// </summary>
        public const string AuthorizationEndpoint = "https://identity-stg.trimble.com/i/oauth2/authorize";

        /// <summary>
        /// Default value for <see cref="OAuthOptions.TokenEndpoint"/>.
        /// </summary>
        public const string TokenEndpoint = "https://identity-stg.trimble.com/i/oauth2/token";

        /// <summary>
        /// Default value for <see cref="OAuthOptions.UserInformationEndpoint"/>.
        /// </summary>
        public const string UserInformationEndpoint = "https://identity-stg.trimble.com/userinfo?schema=openid";
    }
}
