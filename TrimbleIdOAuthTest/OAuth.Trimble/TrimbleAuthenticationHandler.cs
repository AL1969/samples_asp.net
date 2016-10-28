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
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OAuth.Trimble {
    public class TrimbleAuthenticationHandler : OAuthHandler<TrimbleAuthenticationOptions> {
        public TrimbleAuthenticationHandler(HttpClient client)
            : base(client) {
        }


        protected override async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity,
            AuthenticationProperties properties, OAuthTokenResponse tokens) {
            // Note: access tokens and request keys are passed in the querystring for Trimble
            //var address = QueryHelpers.AddQueryString(Options.UserInformationEndpoint, new Dictionary<string, string>() {
            //    ["access_token"] = tokens.AccessToken,
            //    ["key"] = Options.RequestKey,
            //    ["site"] = Options.Site
            //});

            //var request = new HttpRequestMessage(HttpMethod.Get, address);
            //request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            //var response = await Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Context.RequestAborted);
            //response.EnsureSuccessStatusCode();

            //var payload = JObject.Parse(await response.Content.ReadAsStringAsync());

            // Note: the email claim cannot be retrieved from Trimble's user information endpoint.
            // Todo: implement
            //identity.AddOptionalClaim(ClaimTypes.NameIdentifier, TrimbleAuthenticationHelper.GetIdentifier(payload), Options.ClaimsIssuer)
            //        .AddOptionalClaim(ClaimTypes.Name, TrimbleAuthenticationHelper.GetDisplayName(payload), Options.ClaimsIssuer)
            //        .AddOptionalClaim(ClaimTypes.Webpage, TrimbleAuthenticationHelper.GetWebsiteUrl(payload), Options.ClaimsIssuer)
            //        .AddOptionalClaim("urn:Trimble:link", TrimbleAuthenticationHelper.GetLink(payload), Options.ClaimsIssuer);
            //identity.AddClaims(ClaimTypes.NameIdentifier, TrimbleAuthenticationHelper.GetIdentifier(payload), Options.ClaimsIssuer);

            //var principal = new ClaimsPrincipal(identity);
            //var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);

            //var context = new OAuthCreatingTicketContext(ticket, Context, Options, Backchannel, tokens, payload);
            //await Options.Events.CreatingTicket(context);

            //return context.Ticket;
            return null;
        }

        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(string code, string redirectUri) {

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
            //response.

            // Note: Trimble's token endpoint doesn't return JSON but uses application/x-www-form-urlencoded.
            // Since OAuthTokenResponse expects a JSON payload, a JObject is manually created using the returned values.

            string responsestr = await response.Content.ReadAsStringAsync();
            Dictionary<string, string> responseVals = JsonConvert.DeserializeObject<Dictionary<string, string>>(responsestr);

            //JsonConvert
            JObject payload = new JObject();
            //var content = QueryHelpers.ParseQuery(responsestr);
            //foreach (var item in content)
            foreach (var item in responseVals) {
                string ikey = (string)item.Key;
                string ival = (string)item.Value;
                //payload[item.Key] = (string) item.Value;
                payload[ikey] = ival;
            }

            //JToken id_token = payload.GetValue("id_token");
            string sIdtokenEnc;
            responseVals.TryGetValue("id_token", out sIdtokenEnc);

            // To use directly Convert.FromBase64String leads to invalid character exception.
            // This is because there are illegal characters in it (".").
            // That's why we use this as separator for making substrings. One of it includes the information we want.
            var sentences = new List<String>();
            int position = 0;
            int start = 0;
            // Extract sentences from the string.
            do
            {
                position = sIdtokenEnc.IndexOf('.', start);
                if (position >= 0)
                {
                    sentences.Add(sIdtokenEnc.Substring(start, position - start).Trim());
                    start = position + 1;
                }
            } while (position > 0);

            // Display the sentences.
            string sIdtokenJson = null;
            foreach (string sentence in sentences)
            {
                string sToDecode = sentence;
                // do some padding fro the decoder
                while (sToDecode.Length % 4 != 0)
                {
                    sToDecode += "=";
                }
                byte[] bDecoded = Convert.FromBase64String(sToDecode);
                StringBuilder tmpStringBuilder = new StringBuilder();
                tmpStringBuilder.Append(System.Text.UTF8Encoding.UTF8.GetChars(bDecoded));
                string sDecoded = tmpStringBuilder.ToString();
                if (sDecoded.Contains("email"))
                {
                    sIdtokenJson = sDecoded;
                }
            }

            string username = null;
            string firstname = null;
            string lastname = null;
            string email = null;
            if (sIdtokenJson != null)
            {
                sIdtokenJson = sIdtokenJson.Replace("[", "");
                sIdtokenJson = sIdtokenJson.Replace("]", "");
                Dictionary<string, string> idtokenVals = JsonConvert.DeserializeObject<Dictionary<string, string>>(sIdtokenJson);
                foreach (var item in idtokenVals)
                {
                    string ikey = (string)item.Key;
                    string ival = (string)item.Value;
                    if (ikey.Contains("username"))
                    {
                        username = ival;
                    }
                    if (ikey.Contains("firstname"))
                    {
                        firstname = ival;
                    }
                    if (ikey.Contains("lastname"))
                    {
                        lastname = ival;
                    }
                    if (ikey.Contains("email"))
                    {
                        email = ival;
                    }
                }
            }

            if (username == null)
            {
                return OAuthTokenResponse.Failed(new Exception("No username found in ID token."));
            }
            if (email == null)
            {
                return OAuthTokenResponse.Failed(new Exception("No email address found in ID token."));
            }

            payload["username"] = username;
            payload["email"] = email;
            if (firstname == null)
            {
                firstname = "<unknown firstname>";
            }
            payload["firstname"] = firstname;
            if (lastname == null)
            {
                lastname = "<unknown lastname>";
            }
            payload["lastname"] = lastname;

            return OAuthTokenResponse.Success(payload);
        }
    }
}
