using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using TrimbleIdOAuthTest.Data;
using TrimbleIdOAuthTest.Models;
using TrimbleIdOAuthTest.Services;
using Newtonsoft.Json.Linq;

namespace TrimbleIdOAuthTest
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true);

            if (env.IsDevelopment())
            {
                // For more details on using the user secret store see http://go.microsoft.com/fwlink/?LinkID=532709
                builder.AddUserSecrets();

                // This will push telemetry data through Application Insights pipeline faster, allowing you to view results immediately.
                builder.AddApplicationInsightsSettings(developerMode: true);
            }

            builder.AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Add framework services.
            services.AddApplicationInsightsTelemetry(Configuration);

            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            services.AddMvc();

            // Add application services.
            services.AddTransient<IEmailSender, AuthMessageSender>();
            services.AddTransient<ISmsSender, AuthMessageSender>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            app.UseApplicationInsightsRequestTelemetry();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseApplicationInsightsExceptionTelemetry();

            app.UseStaticFiles();

            app.UseIdentity();

            // You must first create an app with GitHub and add its ID and Secret to your user-secrets.
            // https://github.com/settings/applications/
            /*
            app.UseOAuthAuthentication(new OAuthOptions
            {
                AuthenticationScheme = "GitHub-AccessToken",
                DisplayName = "Github-AccessToken",
                ClientId = Configuration["github-token:clientid"],
                ClientSecret = Configuration["github-token:clientsecret"],
                CallbackPath = new PathString("/signin-github-token"),
                AuthorizationEndpoint = "https://github.com/login/oauth/authorize",
                TokenEndpoint = "https://github.com/login/oauth/access_token",
                SaveTokens = true
            });
            */
            /*
            app.UseOAuthAuthentication(new OAuthOptions
            {
                AuthenticationScheme = "TID-AccessToken",
                DisplayName = "TID-AccessToken",
                ClientId = Configuration["Authentication:TrimbleID:ClientId"],
                ClientSecret = Configuration["Authentication:TrimbleID:ClientSecret"],
                CallbackPath = new PathString("/signin-tid-token"),
                AuthorizationEndpoint = "https://identity-stg.trimble.com/i/oauth2/authorize",
                TokenEndpoint = "https://identity-stg.trimble.com/i/oauth2/token",
                SaveTokens = true,
            });
            */
            // You must first create an app with GitHub and add its ID and Secret to your user-secrets.
            // https://github.com/settings/applications/
            app.UseOAuthAuthentication(new OAuthOptions
            {
                AuthenticationScheme = "TID-AccessToken",
                DisplayName = "TID-AccessToken",
                ClientId = Configuration["Authentication:TrimbleID:ClientId"],
                ClientSecret = Configuration["Authentication:TrimbleID:ClientSecret"],
                CallbackPath = new PathString("/signin-tid-token"),
                AuthorizationEndpoint = "https://identity-stg.trimble.com/i/oauth2/authorize",
                TokenEndpoint = "https://identity-stg.trimble.com/i/oauth2/token",
                UserInformationEndpoint = "https://identity-stg.trimble.com/userinfo?schema=openid",
                //ClaimsIssuer = "OAuth2-Github",
                SaveTokens = true,
                // Retrieving user information is unique to each provider.
                Events = new OAuthEvents
                {
                    OnCreatingTicket = async context => { await CreatingTrimbleIdAuthTicket(context); }
                    /*
                    OnCreatingTicket = async context =>
                    {
                        //var tmp_xxxstr = "hello";
                        //Microsoft.AspNetCore.Http.Internal.QueryCollection querycoll = new Microsoft.AspNetCore.Http.Internal.QueryCollection();
                        //async querycoll = context.Request.Query;
                        //object value;
                        //Microsoft.
                        await context.Request.Query.TryGetValue("code", out ValueTask);

                        //var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                        //request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
                        //request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                        // Get the GitHub user
                        //OAuthCreatingTicketContext
                        //Microsoft.AspNetCore.Http.HttpRequest
                        //await HttpRequest.query = context.Request.Query;
                        //var codestr = query.TryGetValue("code");
                        //string codestr = "";
                        //var bCodeFound = query.TryGetValue("code", codestr);

                        //var response = await context.Backchannel.SendAsync(request, context.HttpContext.RequestAborted);
                        //response.EnsureSuccessStatusCode();

                        //var user = JObject.Parse(await response.Content.ReadAsStringAsync());

                        //var identifier = user.Value<string>("id");
                        //if (!string.IsNullOrEmpty(identifier))
                        //{
                        //    context.Identity.AddClaim(new Claim(
                        //        ClaimTypes.NameIdentifier, identifier,
                        //        ClaimValueTypes.String, context.Options.ClaimsIssuer));
                        //}

                        //var userName = user.Value<string>("login");
                    }
                    //OnRedirectToAuthorizationEndpoint = async context =>
                    //{
                    // Get the GitHub user
                    //    var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                    //}
                */
                }
            });

            // Add external authentication middleware below. To configure them please see http://go.microsoft.com/fwlink/?LinkID=532715

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        private static async Task CreatingTrimbleIdAuthTicket(OAuthCreatingTicketContext context)
        {
            StringValues codestr = new StringValues();
            var bFoundCode = context.Request.Query.TryGetValue("code", out codestr);
            string tmp_xxx = "hello";
        }
    }

}
