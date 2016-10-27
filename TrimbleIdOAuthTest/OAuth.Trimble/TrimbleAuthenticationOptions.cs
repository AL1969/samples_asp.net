using System.Net;
using System.Net.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OAuth.Trimble {
    /// <summary>
    /// Defines a set of options used by <see cref="TrimbleAuthenticationHandler"/>.
    /// </summary>
    public class TrimbleAuthenticationOptions : OAuthOptions {
        public TrimbleAuthenticationOptions() {
            AuthenticationScheme = TrimbleAuthenticationDefaults.AuthenticationScheme;
            DisplayName = TrimbleAuthenticationDefaults.DisplayName;
            ClaimsIssuer = TrimbleAuthenticationDefaults.Issuer;

            CallbackPath = new PathString(TrimbleAuthenticationDefaults.CallbackPath);

            AuthorizationEndpoint = TrimbleAuthenticationDefaults.AuthorizationEndpoint;
            TokenEndpoint = TrimbleAuthenticationDefaults.TokenEndpoint;
            UserInformationEndpoint = TrimbleAuthenticationDefaults.UserInformationEndpoint;
            BackchannelHttpHandler = new HttpClientHandler {AutomaticDecompression = DecompressionMethods.GZip};
        }

        /// <summary>
        /// Gets or sets the application request key, obtained
        /// when registering your application with StackApps.
        /// </summary>
        public string RequestKey { get; set; }

        /// <summary>
        /// Gets or sets the site on which the user is registered.
        /// By default, this property is set to "Trimble".
        /// </summary>
        public string Site { get; set; } = "Trimble";
    }
}
