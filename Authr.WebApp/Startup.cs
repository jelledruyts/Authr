using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using Authr.WebApp.Handlers;
using Authr.WebApp.Services;
using Microsoft.ApplicationInsights.Channel;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.AzureADB2C.UI;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Azure.Storage;
using Microsoft.Azure.Storage.Blob;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Logging;

namespace Authr.WebApp
{
    public class Startup
    {
        public Startup(IConfiguration configuration, IWebHostEnvironment webHostEnvironment)
        {
            Configuration = configuration;
            WebHostEnvironment = webHostEnvironment;
        }

        public IConfiguration Configuration { get; }
        public IWebHostEnvironment WebHostEnvironment { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Configure support for the SameSite cookies breaking change.
            services.ConfigureSameSiteCookiePolicy();

            // Set up Application Insights.
            services.AddSingleton<ITelemetryInitializer>(new CloudRoleTelemetryInitializer("Authr Website"));
            services.AddApplicationInsightsTelemetry();

            // Set up a certificate provider.
            var certificateProvider = new FileSystemCertificateProvider(WebHostEnvironment.ContentRootFileProvider);
            certificateProvider.LoadCertificate(Constants.CertificateNames.SigningCertificate, Configuration.GetValue<string>("App:SigningCertificate:Path"), Configuration.GetValue<string>("App:SigningCertificate:Password"));
            certificateProvider.LoadCertificate(Constants.CertificateNames.EncryptionCertificate, Configuration.GetValue<string>("App:EncryptionCertificate:Path"), Configuration.GetValue<string>("App:EncryptionCertificate:Password"));
            services.AddSingleton<ICertificateProvider>(certificateProvider);

            // Configure external Data Protection so that cookies and other secrets can be decoded
            // from different hosting environments (e.g. Web App Slots).
            var dataProtectionConnectionString = Configuration.GetValue<string>("App:DataProtection:ConnectionString");
            var storageAccount = default(CloudStorageAccount);
            if (CloudStorageAccount.TryParse(dataProtectionConnectionString, out storageAccount))
            {
                var blobClient = storageAccount.CreateCloudBlobClient();
                var container = blobClient.GetContainerReference("dataprotection-keys");
                container.CreateIfNotExistsAsync().Wait();
                var blob = container.GetBlockBlobReference("authr-web/keys.xml");
                services.AddDataProtection().PersistKeysToAzureBlobStorage(blob);
            }

            // Set up identity.
            IdentityModelEventSource.ShowPII = true;
            // Don't map any standard OpenID Connect claims to Microsoft-specific claims.
            // See https://leastprivilege.com/2017/11/15/missing-claims-in-the-asp-net-core-2-openid-connect-handler/.
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            services.AddAuthentication(AzureADB2CDefaults.AuthenticationScheme)
                .AddAzureADB2C(options => Configuration.Bind("AzureAdB2C", options));
            services.Configure<OpenIdConnectOptions>(AzureADB2CDefaults.OpenIdScheme, options =>
            {
                // Don't remove any incoming claims.
                options.ClaimActions.Clear();

                // Decouple authentication cookie lifetime from token lifetime.
                options.UseTokenLifetime = false;

                var onTokenValidated = options.Events.OnTokenValidated;
                options.Events.OnTokenValidated = context =>
                {
                    if (onTokenValidated != null)
                    {
                        onTokenValidated(context);
                    }
                    var identity = (ClaimsIdentity)context.Principal.Identity;
                    context.Properties.IsPersistent = true; // Ensure the cookie is persistent across browser sessions.
                    return Task.CompletedTask;
                };
            });
            services.Configure<CookieAuthenticationOptions>(AzureADB2CDefaults.CookieScheme, options =>
            {
                // Stay logged in for 30 days with a sliding window.
                options.ExpireTimeSpan = TimeSpan.FromDays(30);
                options.SlidingExpiration = true;
            });

            // Set up routing and MVC.
            services.AddRouting(options =>
            {
                options.LowercaseUrls = true;
            });
            services.AddControllersWithViews().AddRazorRuntimeCompilation();
            services.AddRazorPages();

            // Set up additional services.
            services.AddHttpClient();
            var userConfigurationConnectionString = Configuration.GetValue<string>("App:UserConfiguration:ConnectionString");
            if (string.IsNullOrWhiteSpace(userConfigurationConnectionString))
            {
                services.AddSingleton<IUserConfigurationProvider>(new InMemoryUserConfigurationProvider());
            }
            else
            {
                services.AddSingleton<IUserConfigurationProvider>(new AzureStorageUserConfigurationProvider(userConfigurationConnectionString));
            }
            var authFlowCacheConnectionString = Configuration.GetValue<string>("App:AuthFlowCache:ConnectionString");
            if (string.IsNullOrWhiteSpace(authFlowCacheConnectionString))
            {
                services.AddSingleton<IAuthFlowCacheProvider>(new InMemoryAuthFlowCacheProvider());
            }
            else
            {
                services.AddSingleton<IAuthFlowCacheProvider>(new AzureStorageAuthFlowCacheProvider(authFlowCacheConnectionString));
            }
            services.AddScoped<AbsoluteUrlProvider>();

            // Set up handlers.
            services.AddScoped<UserConfigurationHandler>();
            services.AddScoped<IdentityServiceHandler>();
            services.AddScoped<OAuth2Handler>();
            services.AddScoped<Saml2Handler>();
            services.AddScoped<WsFederationHandler>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            // Apply support for the SameSite cookies breaking change.
            // This must be called before "UseAuthentication" or anything else that writes cookies.
            app.ApplySameSiteCookiePolicy();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            // Suppress App Insights telemetry from the debug output (see https://github.com/Microsoft/ApplicationInsights-dotnet/issues/310).
            Microsoft.ApplicationInsights.Extensibility.Implementation.TelemetryDebugWriter.IsTracingDisabled = true;

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
                // Razor pages are required by the B2C middleware, e.g. the "AzureADB2C/Account/Error" route.
                endpoints.MapRazorPages();
            });
        }

        private class CloudRoleTelemetryInitializer : ITelemetryInitializer
        {
            private readonly string cloudRoleName;

            public CloudRoleTelemetryInitializer(string cloudRoleName)
            {
                this.cloudRoleName = cloudRoleName;
            }

            public void Initialize(ITelemetry telemetry)
            {
                telemetry.Context.Cloud.RoleName = this.cloudRoleName;
            }
        }
    }
}