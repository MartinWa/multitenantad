using Microsoft.Owin.Security.Cookies;
using Owin;
using System.Linq;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Threading.Tasks;
using System.Configuration;
using TodoListWebApp.DAL;
using System.IdentityModel.Claims;
using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security.Notifications;

namespace TodoListWebApp
{
    public partial class Startup
    {
        private readonly TodoListWebAppContext _db = new TodoListWebAppContext();

        private void ConfigureAuth(IAppBuilder app)
        {
            var clientId = ConfigurationManager.AppSettings["ida:ClientID"];

            //fixed address for multitenant apps in the public cloud
            const string authority = "https://login.microsoftonline.com/common/";

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            var openIdConnectAuthenticationOptions = new OpenIdConnectAuthenticationOptions
            {
                ClientId = clientId,
                Authority = authority,
                TokenValidationParameters = new TokenValidationParameters
                {
                    // instead of using the default validation (validating against a single issuer value, as we do in line of business apps), 
                    // we inject our own multitenant validation logic
                    ValidateIssuer = false,
                },
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    RedirectToIdentityProvider = context => RedirectToIdentityProvider(context),
                    // we use this notification for injecting our custom logic
                    SecurityTokenValidated = context => SecurityTokenValidated(context),
                    AuthenticationFailed = context => AuthenticationFailed(context)
                }
            };
            app.UseOpenIdConnectAuthentication(openIdConnectAuthenticationOptions);
        }

        private static Task AuthenticationFailed(
            AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            context.OwinContext.Response.Redirect("/Home/Error?message=" + context.Exception.Message);
            context.HandleResponse(); // Suppress the exception
            return Task.FromResult(0);
        }

        private Task SecurityTokenValidated(SecurityTokenValidatedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            // retriever caller data from the incoming principal
            var issuer = context.AuthenticationTicket.Identity.FindFirst("iss").Value;
            var upn = context.AuthenticationTicket.Identity.FindFirst(ClaimTypes.Name).Value;
            var tenantId = context.AuthenticationTicket.Identity.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid").Value;

            // the caller comes from an admin-consented, recorded issuer
            var adminConsentedRecordedIssuer = _db.Tenants.FirstOrDefault(a => (a.IssValue == issuer) && a.AdminConsented) == null;

            // the caller is recorded in the _db of users who went through the individual onboardoing
            var userIsOnboarded = _db.Users.FirstOrDefault(b => (b.UPN == upn) && (b.TenantID == tenantId)) == null;

            if (adminConsentedRecordedIssuer && userIsOnboarded)
            {
                // the caller was neither from a trusted issuer or a registered user - throw to block the authentication flow
                throw new SecurityTokenValidationException();
            }
            return Task.FromResult(0);
        }

        private static Task RedirectToIdentityProvider(
            RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            // This ensures that the address used for sign in and sign out is picked up dynamically from the request
            // this allows you to deploy your app (to Azure Web Sites, for example) without having to change settings
            // Remember that the base URL of the address used here must be provisioned in Azure AD beforehand.
            var appBaseUrl = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}";
            context.ProtocolMessage.RedirectUri = appBaseUrl;
            context.ProtocolMessage.PostLogoutRedirectUri = appBaseUrl;
            return Task.FromResult(0);
        }
    }
}