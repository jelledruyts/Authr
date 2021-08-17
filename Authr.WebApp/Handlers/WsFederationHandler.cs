using Authr.WebApp.Models;
using Microsoft.IdentityModel.Protocols.WsFederation;

namespace Authr.WebApp.Handlers
{
    public class WsFederationHandler
    {
        #region SignIn

        public string GetWsFederationSignInHttpPostPageContent(AuthRequest request)
        {
            return GetWsFederationSignInMessage(request).BuildFormPost();
        }

        public string GetWsFederationSignInHttpGetRedirectUrl(AuthRequest request)
        {
            return GetWsFederationSignInMessage(request).BuildRedirectUrl();
        }

        #endregion

        #region Helper Methods

        private WsFederationMessage GetWsFederationSignInMessage(AuthRequest request)
        {
            Guard.NotEmpty(request.Parameters.WsFederationSignOnEndpoint, "The WS-Federation sign-on endpoint must be specified for a WS-Federation 1.2 sign-in request.");
            Guard.NotEmpty(request.Parameters.RedirectUri, "The redirect uri must be specified for a WS-Federation 1.2 sign-in request.");
            Guard.NotEmpty(request.Parameters.WsFederationRealmIdentifier, "The realm identifier must be specified for a WS-Federation 1.2 sign-in request.");
            var message = new WsFederationMessage
            {
                IssuerAddress = request.Parameters.WsFederationSignOnEndpoint,
                Wa = WsFederationConstants.WsFederationActions.SignIn,
                Wtrealm = request.Parameters.WsFederationRealmIdentifier,
                Wreply = request.Parameters.RedirectUri,
                Wctx = Constants.StatePrefixes.Flow + request.FlowId, // Set the request's "wctx" parameter to the flow id so it can be correlated when the response comes back.
            };
            foreach (var item in request.Parameters.GetAdditionalParameters())
            {
                message.SetParameter(item.Key, item.Value);
            }
            return message;
        }

        #endregion
    }
}