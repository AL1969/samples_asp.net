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


        /*
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
        */

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
            var content = QueryHelpers.ParseQuery(responsestr);
            var payload = new JObject();
            foreach (var item in content) {
                string ikey = (string)item.Key;
                string ival = (string)item.Value;
                //payload[item.Key] = (string) item.Value;
            }

            //JToken id_token = payload.GetValue("id_token");
            string sIdtoken;
            responseVals.TryGetValue("id_token", out sIdtoken);

            sIdtoken = "eyJhbGciOiJSUzI1NiJ9.eyJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC9pZGVudGl0eVwvdW5sb2NrVGltZSI6IjAiLCJzdWIiOiJhbmRyZWFzX2xhbmdAdHJpbWJsZS5jb20iLCJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC9hY2NvdW50bmFtZSI6InRyaW1ibGUuY29tIiwiYXpwIjoiSEE3NG02UFBZN1NzX19zejBVTVVER2ltTVlZYSIsImh0dHA6XC9cL3dzbzIub3JnXC9jbGFpbXNcL2ZpcnN0bmFtZSI6IkFuZHJlYXMiLCJhdF9oYXNoIjoibDBJQ21MNjRORndRY2FNNVVYb2R3dyIsImlzcyI6Imh0dHBzOlwvXC9pZGVudGl0eS1zdGcudHJpbWJsZS5jb20iLCJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC9sYXN0bmFtZSI6IkxhbmciLCJodHRwOlwvXC93c28yLm9yZ1wvY2xhaW1zXC90ZWxlcGhvbmUiOiIrNDk4OTg5MDU3MTQ4NCIsImh0dHA6XC9cL3dzbzIub3JnXC9jbGFpbXNcL3V1aWQiOiI2YmM5YTllMS1hNTI3LTQ0NWMtYWNlNS1lZTEyMTZkNmRjMjgiLCJpYXQiOjE0Nzc1Nzg3NzcsImh0dHA6XC9cL3dzbzIub3JnXC9jbGFpbXNcL2dpdmVubmFtZSI6IkFuZHJlYXMiLCJhdXRoX3RpbWUiOjE0Nzc1NzQ1MDAsImV4cCI6MTQ3NzU4MjM3NywiaHR0cDpcL1wvd3NvMi5vcmdcL2NsYWltc1wvaWRlbnRpdHlcL2ZhaWxlZExvZ2luQXR0ZW1wdHMiOiIwIiwiaHR0cDpcL1wvd3NvMi5vcmdcL2NsYWltc1wvaWRlbnRpdHlcL2FjY291bnRMb2NrZWQiOiJmYWxzZSIsImh0dHA6XC9cL3dzbzIub3JnXC9jbGFpbXNcL2NvdW50cnkiOiJHZXJtYW55IiwiYXVkIjpbIkhBNzRtNlBQWTdTc19fc3owVU1VREdpbU1ZWWEiXSwiaHR0cDpcL1wvd3NvMi5vcmdcL2NsYWltc1wvZW1haWxhZGRyZXNzIjoiYW5kcmVhc19sYW5nQHRyaW1ibGUuY29tIiwiaHR0cDpcL1wvd3NvMi5vcmdcL2NsYWltc1wvYWNjb3VudHVzZXJuYW1lIjoiYW5kcmVhc19sYW5nIn0.pI82";
            char[] sIdtokenChars = sIdtoken.ToCharArray();
            //XBase64.Base64Decoder(sIdtokenChars);
            XBase64.Base64Decoder myDecoder = new XBase64.Base64Decoder(sIdtokenChars);
            byte[] temp = myDecoder.GetDecoded();
            //Base64Decoder myDecoder = new Base64Decoder(data);

            StringBuilder sb = new StringBuilder();

            //byte[] temp = myDecoder.GetDecoded();
            sb.Append(System.Text.UTF8Encoding.UTF8.GetChars(temp));
            //sb.Append(System.Text.ASCIIEncoding.ASCII.GetChars(temp));

            string sTmpDecoded = sb.ToString();


            //char[] carr = sIdtoken.ToCharArray();
            //int len = carr.Length;
            //byte[] convbytes = Convert.FromBase64CharArray(carr, 0, len);

            //byte[] inbytes = Encoding.ASCII.GetChars()
            //int len = inbytes.Length;
            //byte[] convbytes = Convert.FromBase64CharArray(inbytes, 0, len);

            //string idtokenstr = (string) payload.GetValue("id_token");
            //string sIdJson = Convert.FromBase64String(sIdtoken).ToString();
            byte[] convbytes;
            try
            {
                convbytes = Convert.FromBase64String(sIdtoken);
            }
            catch (Exception)
            {

            }
            //byte[] convbytes = Convert.FromBase64CharArray(sIdtoken.ToCharArray());


            /*
             * 			var req = https.request(options, (res) => {
                            res.setEncoding('utf-8');
                            res.on('data', (chunk) => {
                                //requestTC_JWT(JSON.parse(chunk).id_token);
                                console.log("requestTID_JWT - response BODY:\n**********\n" + chunk + "\n**********\n");
                                var id_token = JSON.parse(chunk).id_token;
                                console.log("requestTID_JWT - response id_token:\n**********\n" + id_token + "\n**********\n");
                                var id_token_buf = new Buffer(id_token, 'base64');
                                console.log("requestTID_JWT - response id_token_buf tostring:\n**********\n" + id_token_buf.toString('utf8') + "\n**********\n");
                                browserWindow.loadURL(redirectURL);
                            });
                            res.on('end', () => {
                                console.log("requestTID_JWT - response: No more data in response.");
                            });
                        });

             */


            return OAuthTokenResponse.Success(payload);
        }
    }
}
