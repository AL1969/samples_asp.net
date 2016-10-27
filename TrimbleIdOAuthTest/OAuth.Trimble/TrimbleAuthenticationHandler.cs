using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
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

            /*
                        string redirUrlEnc = System.Net.WebUtility.UrlEncode(redirUrl);
                        string sPostUrl = "https://identity-stg.trimble.com/i/oauth2/token";
                        var request = new HttpRequestMessage(HttpMethod.Post, sPostUrl);

                        string recAccessToken = context.AccessToken;
                        string testAccessTokenStr = "vHDnG98OicY1asmxzcVFYYk_UJMa:UekcdFkvAWALmTrDSbBf7gVGVIsa";
                        byte[] testAccessToken = System.Text.Encoding.UTF8.GetBytes(testAccessTokenStr);
                        string testAccessTokenBas64 = "Basic " + Microsoft.AspNetCore.Authentication.Base64UrlTextEncoder.Encode(testAccessToken);

                        // overwrite with values from JS
                        //codestr = "bc8e9e4216d746693feb673491776";
                        //redirUrl = "http://localhost:8888/auth_trimbleid/oauth_after.html";
                        redirUrlEnc = "http%3A%2F%2Flocalhost%3A8888%2Fauth_trimbleid%2Foauth_after.html";
                        testAccessTokenBas64 = "Basic SEE3NG02UFBZN1NzX19zejBVTVVER2ltTVlZYTpYcFZxQmYyY1kyZ0UwVzdxeUhZOXNPdFBOZmdh";

                        // see http://stackoverflow.com/questions/15176538/net-httpclient-how-to-post-string-value
                        //     http://www.asp.net/web-api/overview/advanced/calling-a-web-api-from-a-net-client
                        //     http://developer.spotify.com/web-api/authorization-guide/
                        //     http://tools.ietf.org/html/rfc6749#section-4.1.3
                        //string contentstr = "grant_type=authorization_code&tenantDomain=trimble.com&code=" + codestr + "&redirect_uri=" + redirUrlEnc;
                        string contentstr = "grant_type=authorization_code&tenantDomain=trimble.com&code=" + codestr + "&redirect_uri=" + redirUrlEnc;
                        //var content = new FormUrlEncodedContent(pairs);
                        var content = new StringContent(contentstr);
                        content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

                        HttpClient client = new HttpClient();
                        client.BaseAddress = new Uri("https://identity-stg.trimble.com");
                        client.DefaultRequestHeaders.Add("Cache-Control", "no-cache");
                        client.DefaultRequestHeaders.Add("Authorization", testAccessTokenBas64);
                        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                        client.DefaultRequestHeaders.Add("Host", "identity-stg.trimble.com");

                        var response = client.PostAsync("/i/oauth2/token", content).Result;




                        var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Options.ClientId}:{Options.ClientSecret}"));

            var request = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);


             */

            var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Options.ClientId}:{Options.ClientSecret}"));

            var request = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
            request.Content = new FormUrlEncodedContent(new Dictionary<string, string> {
                ["grant_type"] = "authorization_code",
                ["tenantDomain"] = "trimble.com",
                ["code"] = code,
                ["redirect_uri"] = redirectUri
            });
            request.Headers.Add("Cache-Control", "no-cache");
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
            //request.Headers.Add("Authorization", testAccessTokenBas64);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Add("Host", "identity-stg.trimble.com");

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


            string responsestr = await response.Content.ReadAsStringAsync();

            //var content = QueryHelpers.ParseQuery(await response.Content.ReadAsStringAsync());
            var content = QueryHelpers.ParseQuery(responsestr);

            var payload = new JObject();
            foreach (var item in content) {
                payload[item.Key] = (string) item.Value;
            }

            return OAuthTokenResponse.Success(payload);
        }
    }
}
