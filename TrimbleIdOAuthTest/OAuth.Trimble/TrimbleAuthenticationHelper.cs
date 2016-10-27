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
        public static string GetIdentifier(JObject user) => user["items"]?[0]?.Value<string>("account_id");

        /// <summary>
        /// Gets the display name corresponding to the authenticated user.
        /// </summary>
        public static string GetDisplayName(JObject user) => user["items"]?[0]?.Value<string>("display_name");

        /// <summary>
        /// Gets the URL corresponding to the authenticated user.
        /// </summary>
        public static string GetLink(JObject user) => user["items"]?[0]?.Value<string>("link");

        /// <summary>
        /// Gets the website URL associated with the authenticated user.
        /// </summary>
        public static string GetWebsiteUrl(JObject user) => user["items"]?[0]?.Value<string>("website_url");
    }
}
