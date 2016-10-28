//using JetBrains.Annotations;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OAuth.Trimble {
    /// <summary>
    /// Contains static methods that allow to extract user's information from a <see cref="JObject"/>
    /// instance retrieved from Trimble after a successful authentication process.
    /// </summary>
    public static class TrimbleAuthenticationHelper {
        /// <summary>
        /// Gets the identifier corresponding to the authenticated user.
        /// </summary>
        public static string GetIdentifier(JObject user) => user.Value<string>("username");

        /// <summary>
        /// Gets the internal response code from the web request
        /// </summary>
        public static JObject GetError(JObject user) => user.Value<JObject>("error");

        /// <summary>
        /// Gets the login corresponding to the authenticated user.
        /// </summary>
        public static string GetName(JObject user) => user.Value<string>("firstname");

        /// <summary>
        /// Gets the email address corresponding to the authenticated user.
        /// </summary>
        public static string GetEmail(JObject user) => user.Value<string>("email");
    }
}
