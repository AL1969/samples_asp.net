using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
//using AspNet.Security.OAuth.Extensions;
//using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OAuth.Trimble {
    public class TrimbleAuthenticationHandler : OAuthHandler<TrimbleAuthenticationOptions> {
        public TrimbleAuthenticationHandler(HttpClient client)
            : base(client) {
        }

        protected override async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity,
            AuthenticationProperties properties, OAuthTokenResponse tokens) {
            // Note: access tokens and request keys are passed in the querystring for Trimble
            var address = QueryHelpers.AddQueryString(Options.UserInformationEndpoint, new Dictionary<string, string>() {
                ["access_token"] = tokens.AccessToken,
                ["key"] = Options.RequestKey,
                ["site"] = Options.Site
            });

            var request = new HttpRequestMessage(HttpMethod.Get, address);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var response = await Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Context.RequestAborted);
            response.EnsureSuccessStatusCode();

            var payload = JObject.Parse(await response.Content.ReadAsStringAsync());

            // Note: the email claim cannot be retrieved from Trimble's user information endpoint.
            // Todo: implement
            //identity.AddOptionalClaim(ClaimTypes.NameIdentifier, TrimbleAuthenticationHelper.GetIdentifier(payload), Options.ClaimsIssuer)
            //        .AddOptionalClaim(ClaimTypes.Name, TrimbleAuthenticationHelper.GetDisplayName(payload), Options.ClaimsIssuer)
            //        .AddOptionalClaim(ClaimTypes.Webpage, TrimbleAuthenticationHelper.GetWebsiteUrl(payload), Options.ClaimsIssuer)
            //        .AddOptionalClaim("urn:Trimble:link", TrimbleAuthenticationHelper.GetLink(payload), Options.ClaimsIssuer);

            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);

            var context = new OAuthCreatingTicketContext(ticket, Context, Options, Backchannel, tokens, payload);
            await Options.Events.CreatingTicket(context);

            return context.Ticket;
        }

        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(string code, string redirectUri) {
            var request = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
            request.Content = new FormUrlEncodedContent(new Dictionary<string, string> {
                ["client_id"] = Options.ClientId,
                ["redirect_uri"] = redirectUri,
                ["client_secret"] = Options.ClientSecret,
                ["code"] = code,
                ["grant_type"] = "authorization_code"
            });

            var response = await Backchannel.SendAsync(request, Context.RequestAborted);
            if (!response.IsSuccessStatusCode) {
                Logger.LogError("An error occurred when retrieving an access token: the remote server " +
                               "returned a {Status} response with the following payload: {Headers} {Body}.",
                               /* Status: */ response.StatusCode,
                               /* Headers: */ response.Headers.ToString(),
                               /* Body: */ await response.Content.ReadAsStringAsync());

                return OAuthTokenResponse.Failed(new Exception("An error occurred when retrieving an access token."));
            }

            // Note: Trimble's token endpoint doesn't return JSON but uses application/x-www-form-urlencoded.
            // Since OAuthTokenResponse expects a JSON payload, a JObject is manually created using the returned values.
            var content = QueryHelpers.ParseQuery(await response.Content.ReadAsStringAsync());

            var payload = new JObject();
            foreach (var item in content) {
                payload[item.Key] = (string) item.Value;
            }

            return OAuthTokenResponse.Success(payload);
        }
    }
}
