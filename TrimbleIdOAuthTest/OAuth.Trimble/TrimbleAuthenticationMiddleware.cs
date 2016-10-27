using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
//using JetBrains.Annotations;

namespace AspNet.Security.OAuth.Trimble {
    public class TrimbleAuthenticationMiddleware : OAuthMiddleware<TrimbleAuthenticationOptions> {
        public TrimbleAuthenticationMiddleware(
            RequestDelegate next,
            IDataProtectionProvider dataProtectionProvider,
            ILoggerFactory loggerFactory,
            UrlEncoder encoder,
            IOptions<SharedAuthenticationOptions> sharedOptions,
            IOptions<TrimbleAuthenticationOptions> options)
            : base(next, dataProtectionProvider, loggerFactory, encoder, sharedOptions, options) {
        }

        protected override AuthenticationHandler<TrimbleAuthenticationOptions> CreateHandler() {
            return new TrimbleAuthenticationHandler(Backchannel);
        }
    }
}
