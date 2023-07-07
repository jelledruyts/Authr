using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Authr.WebApp.Handlers;
using Authr.WebApp.Models;
using Authr.WebApp.Services;
using Microsoft.ApplicationInsights;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Authr.WebApp.Controllers
{
    public class HomeController : Controller
    {
        #region Fields

        private readonly ILogger<HomeController> logger;
        private readonly IConfiguration configuration;
        private readonly IAuthFlowCacheProvider authFlowCacheProvider;
        private readonly TelemetryClient telemetryClient;
        private readonly AbsoluteUrlProvider absoluteUrlProvider;
        private readonly UserConfigurationHandler userConfigurationHandler;
        private readonly IdentityServiceHandler identityServiceImportHandler;
        private readonly OAuth2Handler oauth2Handler;
        private readonly Saml2Handler saml2Handler;
        private readonly WsFederationHandler wsFederationHandler;

        #endregion

        #region Constructors

        public HomeController(ILogger<HomeController> logger, IConfiguration configuration, IAuthFlowCacheProvider authFlowCacheProvider, TelemetryClient telemetryClient, AbsoluteUrlProvider absoluteUrlProvider, UserConfigurationHandler userConfigurationHandler, IdentityServiceHandler identityServiceImportHandler, OAuth2Handler oauth2Handler, Saml2Handler saml2Handler, WsFederationHandler wsFederationHandler)
        {
            this.logger = logger;
            this.configuration = configuration;
            this.authFlowCacheProvider = authFlowCacheProvider;
            this.telemetryClient = telemetryClient;
            this.absoluteUrlProvider = absoluteUrlProvider;
            this.userConfigurationHandler = userConfigurationHandler;
            this.identityServiceImportHandler = identityServiceImportHandler;
            this.oauth2Handler = oauth2Handler;
            this.saml2Handler = saml2Handler;
            this.wsFederationHandler = wsFederationHandler;
        }

        #endregion

        #region Action Methods

        [Route(nameof(About))]
        public IActionResult About()
        {
            return View();
        }

        [Route(nameof(Token))]
        public IActionResult Token()
        {
            return View();
        }

        [Route(nameof(Configuration))]
        public async Task<IActionResult> Configuration()
        {
            var model = await this.userConfigurationHandler.GetUserConfigurationAsync(this.User.GetUserId());
            return View(model);
        }

        [Route(nameof(Privacy))]
        public IActionResult Privacy()
        {
            return View();
        }

        [Route(nameof(Terms))]
        public IActionResult Terms()
        {
            return View();
        }

        [Route("metadata/saml2")]
        public async Task<IActionResult> MetadataSaml2()
        {
            var metadataXml = await this.saml2Handler.GetMetadataXmlAsync();
            return Content(metadataXml, "text/xml");
        }

        [Route(nameof(Error))]
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [Route("")]
        public Task<IActionResult> Index(AuthRequestParameters requestParameters, AuthResponseParameters responseParameters)
        {
            var canonicalDomain = this.configuration.GetValue<string>("App:Domains:CanonicalDomain");
            var obsoleteDomains = this.configuration.GetValue<string>("App:Domains:ObsoleteDomains");
            if (canonicalDomain != null && obsoleteDomains != null)
            {
                // If a GET request to the site root and without any parameters comes in on an obsolete domain, redirect to the canonical domain.
                if (this.Request.Path == "/" && this.Request.Query.Count == 0 && obsoleteDomains.Split(';').Any(d => this.Request.Host.Host.Equals(d, StringComparison.OrdinalIgnoreCase)))
                {
                    return Task.FromResult((IActionResult)RedirectPermanent($"https://{canonicalDomain}"));
                }
            }
            // Whenever a GET comes in, bind the possibly matching parameters to a request or response (done automatically
            // by model binding) and attempt to handle either.
            return HandlePageRequestAsync(requestParameters, responseParameters);
        }

        [Route("")]
        [HttpPost]
        public Task<IActionResult> IndexPost(AuthRequestParameters requestParameters, AuthResponseParameters responseParameters)
        {
            // Whenever a POST comes in, bind the possibly matching parameters to a request or response (done automatically
            // by model binding) and attempt to handle either.
            return HandlePageRequestAsync(requestParameters, responseParameters);
        }

        [Route("api/request")]
        [HttpPost]
        public Task<AuthViewModel> SubmitRequest([FromBody] ApiClientRequest request)
        {
            // This is an API call, do not return a page or redirect the browser but return the data only.
            return HandleApiRequestAsync(request, null);
        }

        [Route("api/response")]
        [HttpPost]
        public Task<AuthViewModel> SubmitResponse([FromBody] AuthResponseParameters responseParameters)
        {
            // This is an API call, do not return a page or redirect the browser but return the data only.
            return HandleApiRequestAsync(null, responseParameters);
        }

        [Route("api/userConfiguration")]
        [HttpPost]
        public async Task<IActionResult> SaveUserConfiguration([FromBody] UserConfiguration userConfiguration)
        {
            if (!this.User.Identity.IsAuthenticated)
            {
                this.logger.LogWarning("A request was made to save user configuration but the user is not authenticated.");
                return Unauthorized();
            }

            // Ensure the User ID cannot be spoofed.
            userConfiguration.UserId = this.User.GetUserId();
            await this.userConfigurationHandler.SaveAsync(userConfiguration);
            this.telemetryClient.TrackEvent("UserConfiguration.Saved");
            return Ok(userConfiguration);
        }

        [Route("api/identityServiceImportRequest")]
        [HttpPost]
        public async Task<IdentityService> SubmitIdentityServiceImportRequest([FromBody] IdentityServiceImportRequestParameters identityServiceImportRequestParameters)
        {
            return await this.identityServiceImportHandler.HandleImportIdentityServiceRequestAsync(identityServiceImportRequestParameters);
        }

        [Route("api/decryptToken")]
        [HttpPost]
        public async Task<string> DecryptToken([FromBody] DecryptTokenRequest request)
        {
            return await this.saml2Handler.DecryptTokenAsync(request);
        }

        #endregion

        #region Page & API Request Handling

        private async Task<IActionResult> HandlePageRequestAsync(AuthRequestParameters requestParameters, AuthResponseParameters responseParameters)
        {
            var model = await HandleCoreAsync(requestParameters, responseParameters);
            if (!string.IsNullOrWhiteSpace(model.RequestedRedirectUrl))
            {
                // The result of a request was to redirect the browser, send a redirect response.
                return Redirect(model.RequestedRedirectUrl);
            }
            else if (!string.IsNullOrWhiteSpace(model.RequestedPageContent))
            {
                // The result of a request was the full page content, return that directly.
                return Content(model.RequestedPageContent, "text/html");
            }
            else
            {
                // Render the regular page, optionally with user configuration if the user was signed in.
                if (this.User.Identity.IsAuthenticated)
                {
                    model.UserConfiguration = await this.userConfigurationHandler.GetUserConfigurationAsync(this.User.GetUserId());
                }
                return View(nameof(Index), model);
            }
        }

        private async Task<AuthViewModel> HandleApiRequestAsync(ApiClientRequest request, AuthResponseParameters responseParameters)
        {
            var userConfiguration = default(UserConfiguration);
            if (request != null && request.Options != null)
            {
                if (request.Options.SaveIdentityService || request.Options.SaveClientApplication || request.Options.SaveRequestTemplate)
                {
                    if (!this.User.Identity.IsAuthenticated)
                    {
                        this.logger.LogWarning("A request was made to save certain request options but the user is not authenticated.");
                    }
                    else
                    {
                        var userId = this.User.GetUserId();
                        userConfiguration = await this.userConfigurationHandler.UpdateAndSaveAsync(userId, request);
                        this.telemetryClient.TrackEvent("UserConfiguration.Saved");
                    }
                }
            }
            var model = await HandleCoreAsync(request?.RequestParameters, responseParameters);
            if (userConfiguration != null)
            {
                model.UserConfiguration = userConfiguration;
            }
            return model;
        }

        #endregion

        #region Core Auth Handling

        private async Task<AuthViewModel> HandleCoreAsync(AuthRequestParameters requestParameters, AuthResponseParameters responseParameters)
        {
            var model = new AuthViewModel();
            try
            {
                if (responseParameters != null && !responseParameters.IsEmpty())
                {
                    // We have a response to a previously initiated flow, attempt to determine the flow id from an incoming "State", "RelayState" or "Wctx" parameter.
                    var flowId = default(string);
                    if (responseParameters.State != null && responseParameters.State.StartsWith(Constants.StatePrefixes.Flow))
                    {
                        flowId = responseParameters.State.Substring(Constants.StatePrefixes.Flow.Length);
                    }
                    if (string.IsNullOrWhiteSpace(flowId) && responseParameters.RelayState != null && responseParameters.RelayState.StartsWith(Constants.StatePrefixes.Flow))
                    {
                        flowId = responseParameters.RelayState.Substring(Constants.StatePrefixes.Flow.Length);
                    }
                    if (string.IsNullOrWhiteSpace(flowId) && responseParameters.Wctx != null && responseParameters.Wctx.StartsWith(Constants.StatePrefixes.Flow))
                    {
                        flowId = responseParameters.Wctx.Substring(Constants.StatePrefixes.Flow.Length);
                    }

                    // Retrieve the flow details from cache.
                    var flow = default(AuthFlow);
                    var flowReferenceToRemoveFromCacheWhenComplete = default(string);
                    if (!string.IsNullOrWhiteSpace(flowId))
                    {
                        // We have a state correlation id, this a response to an existing request we should have full request details for.
                        // The flow id should be in the State parameter as passed in during the request original.
                        flow = await this.authFlowCacheProvider.GetAuthFlowAsync(flowId);
                        if (flow != null)
                        {
                            flowReferenceToRemoveFromCacheWhenComplete = flow.Id;
                        }
                        else
                        {
                            this.logger.LogWarning($"Flow with original request not found for flow id \"{flowId}\".");
                        }
                    }

                    // If no flow was found, track it as an externally initiated request.
                    if (flow == null)
                    {
                        // We have a response to a flow that was not originated here (e.g. it could be IdP-initiated).
                        flow = new AuthFlow { UserId = this.User.GetUserId() };
                        this.telemetryClient.TrackEvent("AuthFlow.Initiated", new Dictionary<string, string> { { "AuthFlowId", flow.Id }, { "RequestType", flow.RequestType } });
                        flow.AddExternallyInitiatedRequest();
                    }

                    // Check that the request belongs to the current user if signed in.
                    if (!string.IsNullOrWhiteSpace(flow.UserId) && flow.UserId != this.User.GetUserId())
                    {
                        this.logger.LogWarning($"Flow \"{flow.Id}\" was requested by user \"{flow.UserId}\" but a response is now being processed by user \"{this.User.GetUserId()}\".");
                        throw new InvalidOperationException("You don't have permissions to this flow.");
                    }

                    var originalRequest = flow.Requests.Last();
                    model.Flow = flow;
                    model.RequestParameters = originalRequest.Parameters;

                    // Populate the response from the incoming parameters.
                    var response = AuthResponse.FromAuthResponseParameters(responseParameters);
                    originalRequest.Response = response;
                    this.telemetryClient.TrackEvent("AuthResponse.Received", new Dictionary<string, string> { { "AuthFlowId", flow.Id }, { "RequestType", originalRequest.Parameters?.RequestType } }, new Dictionary<string, double> { { "TimeTakenMs", (originalRequest.Response.TimeCreated - originalRequest.TimeCreated).TotalMilliseconds } });

                    // If there is an authorization code response, redeem it immediately for the access token.
                    if (!string.IsNullOrWhiteSpace(responseParameters.AuthorizationCode))
                    {
                        if (originalRequest.IsInitiatedExternally)
                        {
                            originalRequest.Response = AuthResponse.FromError("An authorization code was received but the request was initiated externally, cannot redeem it for an access token.", $"Authorization code: \"{responseParameters.AuthorizationCode}\".");
                        }
                        else
                        {
                            var authorizationCodeRequestParameters = new AuthRequestParameters(originalRequest.Parameters);
                            authorizationCodeRequestParameters.RequestType = Constants.RequestTypes.AuthorizationCode;
                            authorizationCodeRequestParameters.AuthorizationCode = responseParameters.AuthorizationCode;
                            var authorizationCodeRequest = flow.AddRequest(authorizationCodeRequestParameters);
                            this.telemetryClient.TrackEvent("AuthRequest.Sent", new Dictionary<string, string> { { "AuthFlowId", flow.Id }, { "RequestType", authorizationCodeRequest.Parameters?.RequestType } });
                            var authorizationCodeResponse = await this.oauth2Handler.HandleAuthorizationCodeResponseAsync(authorizationCodeRequest.Parameters, originalRequest.CodeVerifier);
                            authorizationCodeRequest.Response = authorizationCodeResponse;
                            this.telemetryClient.TrackEvent("AuthResponse.Received", new Dictionary<string, string> { { "AuthFlowId", flow.Id }, { "RequestType", authorizationCodeRequest.Parameters?.RequestType } }, new Dictionary<string, double> { { "TimeTakenMs", (authorizationCodeRequest.Response.TimeCreated - authorizationCodeRequest.TimeCreated).TotalMilliseconds } });
                        }
                    }
                    flow.IsComplete = true;
                    flow.TimeCompleted = DateTimeOffset.UtcNow;
                    this.telemetryClient.TrackEvent("AuthFlow.Completed", new Dictionary<string, string> { { "AuthFlowId", flow.Id }, { "RequestType", flow.RequestType } }, new Dictionary<string, double> { { "TimeTakenMs", (flow.TimeCompleted.Value - flow.TimeCreated).TotalMilliseconds } });
                    if (flow.IsComplete && !string.IsNullOrEmpty(flowReferenceToRemoveFromCacheWhenComplete))
                    {
                        await this.authFlowCacheProvider.RemoveAuthFlowAsync(flowReferenceToRemoveFromCacheWhenComplete);
                    }

                    // Set the response to the last relevant response received.
                    model.Response = flow.Requests.Last().Response;
                }
                else if (requestParameters != null && !string.IsNullOrWhiteSpace(requestParameters.RequestType))
                {
                    // Set defaults if omitted.
                    if (string.IsNullOrWhiteSpace(requestParameters.RedirectUri))
                    {
                        requestParameters.RedirectUri = this.absoluteUrlProvider.GetAbsoluteRootUrl();
                    }
                    // Import Identity Service if requested.
                    if (!string.IsNullOrWhiteSpace(requestParameters.ImportType))
                    {
                        var identityService = await SubmitIdentityServiceImportRequest(requestParameters);
                        if (identityService != null)
                        {
                            requestParameters.AuthorizationEndpoint = identityService.AuthorizationEndpoint;
                            requestParameters.TokenEndpoint = identityService.TokenEndpoint;
                            requestParameters.DeviceCodeEndpoint = identityService.DeviceCodeEndpoint;
                            requestParameters.SamlSignOnEndpoint = identityService.SamlSignOnEndpoint;
                            requestParameters.SamlLogoutEndpoint = identityService.SamlLogoutEndpoint;
                            requestParameters.WsFederationSignOnEndpoint = identityService.WsFederationSignOnEndpoint;
                        }
                    }

                    if (string.Equals(requestParameters.RequestAction, Constants.RequestActions.GenerateLink, StringComparison.InvariantCultureIgnoreCase))
                    {
                        var clone = new AuthRequestParameters(requestParameters);
                        clone.RequestAction = null; // Don't generate a link with the "generate a link" request action.
                        model.GeneratedLink = Url.Action(nameof(Index), clone);
                    }
                    else if (string.Equals(Request.Method, HttpMethod.Post.Method, StringComparison.InvariantCultureIgnoreCase)
                        || string.Equals(requestParameters.RequestAction, Constants.RequestActions.PerformRequest, StringComparison.InvariantCultureIgnoreCase))
                    {
                        // Look up an existing flow if possible.
                        var flowReferenceToRemoveFromCacheWhenComplete = default(string);
                        var flow = default(AuthFlow);
                        if (requestParameters.RequestType == Constants.RequestTypes.DeviceToken && !string.IsNullOrWhiteSpace(requestParameters.DeviceCode))
                        {
                            flow = await this.authFlowCacheProvider.GetAuthFlowAsync(requestParameters.DeviceCode);
                            flowReferenceToRemoveFromCacheWhenComplete = (flow == null ? null : requestParameters.DeviceCode);
                        }
                        if (flow == null)
                        {
                            flow = new AuthFlow { UserId = this.User.GetUserId(), RequestType = requestParameters.RequestType };
                            this.telemetryClient.TrackEvent("AuthFlow.Initiated", new Dictionary<string, string> { { "AuthFlowId", flow.Id }, { "RequestType", flow.RequestType } });
                        }
                        model.Flow = flow;
                        model.RequestParameters = requestParameters;
                        var request = flow.AddRequest(requestParameters);
                        this.telemetryClient.TrackEvent("AuthRequest.Sent", new Dictionary<string, string> { { "AuthFlowId", flow.Id }, { "RequestType", request.Parameters?.RequestType } });

                        // Determine which flow to execute.
                        if (requestParameters.RequestType == Constants.RequestTypes.OpenIdConnect || requestParameters.RequestType == Constants.RequestTypes.Implicit || requestParameters.RequestType == Constants.RequestTypes.AuthorizationCode)
                        {
                            model.RequestedRedirectUrl = this.oauth2Handler.GetAuthorizationEndpointRequestUrl(request);
                            request.RequestedRedirectUrl = model.RequestedRedirectUrl;
                            await this.authFlowCacheProvider.SetAuthFlowAsync(flow.Id, flow);
                        }
                        else if (requestParameters.RequestType == Constants.RequestTypes.ClientCredentials)
                        {
                            request.Response = await this.oauth2Handler.HandleClientCredentialsRequestAsync(requestParameters);
                            flow.IsComplete = true;
                        }
                        else if (requestParameters.RequestType == Constants.RequestTypes.RefreshToken)
                        {
                            request.Response = await this.oauth2Handler.HandleRefreshTokenRequestAsync(requestParameters);
                            flow.IsComplete = true;
                        }
                        else if (requestParameters.RequestType == Constants.RequestTypes.DeviceCode)
                        {
                            request.Response = await this.oauth2Handler.HandleDeviceCodeRequestAsync(requestParameters);
                            if (string.IsNullOrWhiteSpace(request.Response.DeviceCode))
                            {
                                flow.IsComplete = true;
                            }
                            else
                            {
                                // This is just the first part of the flow, the device token still has to be requested.
                                // Keep the flow in cache until the device code is exchanged for the token.
                                await this.authFlowCacheProvider.SetAuthFlowAsync(request.Response.DeviceCode, flow);
                                flow.IsComplete = false;
                            }
                        }
                        else if (requestParameters.RequestType == Constants.RequestTypes.DeviceToken)
                        {
                            request.Response = await this.oauth2Handler.HandleDeviceTokenRequestAsync(requestParameters);
                            if (string.IsNullOrWhiteSpace(request.Response.Error))
                            {
                                flow.IsComplete = true;
                            }
                            else
                            {
                                // An error occurred so the flow is not complete yet, save changes.
                                await this.authFlowCacheProvider.SetAuthFlowAsync(requestParameters.DeviceCode, flow);
                            }
                        }
                        else if (requestParameters.RequestType == Constants.RequestTypes.ResourceOwnerPasswordCredentials)
                        {
                            request.Response = await this.oauth2Handler.HandleResourceOwnerPasswordCredentialsRequestAsync(requestParameters);
                            flow.IsComplete = true;
                        }
                        else if (requestParameters.RequestType == Constants.RequestTypes.OnBehalfOf)
                        {
                            request.Response = await this.oauth2Handler.HandleOnBehalfOfRequestAsync(requestParameters);
                            flow.IsComplete = true;
                        }
                        else if (requestParameters.RequestType == Constants.RequestTypes.OAuth2CustomGrant)
                        {
                            request.Response = await this.oauth2Handler.HandleCustomGrantRequestAsync(requestParameters);
                            flow.IsComplete = true;
                        }
                        else if (requestParameters.RequestType == Constants.RequestTypes.Saml2AuthnRequest)
                        {
                            if (requestParameters.RequestMethod == Constants.RequestMethods.HttpPost)
                            {
                                var postContent = await this.saml2Handler.GetAuthenticationRequestHttpPostPageContentAsync(request);
                                model.RequestedPageContent = postContent;
                            }
                            else
                            {
                                var redirectUrl = await this.saml2Handler.GetAuthenticationRequestHttpGetRedirectUrl(request);
                                model.RequestedRedirectUrl = redirectUrl;
                                request.RequestedRedirectUrl = model.RequestedRedirectUrl;
                            }
                            await this.authFlowCacheProvider.SetAuthFlowAsync(flow.Id, flow);
                        }
                        else if (requestParameters.RequestType == Constants.RequestTypes.Saml2LogoutRequest)
                        {
                            if (requestParameters.RequestMethod == Constants.RequestMethods.HttpPost)
                            {
                                var postContent = await this.saml2Handler.GetLogoutRequestHttpPostPageContentAsync(request);
                                model.RequestedPageContent = postContent;
                            }
                            else
                            {
                                var redirectUrl = await this.saml2Handler.GetLogoutRequestHttpGetRedirectUrl(request);
                                model.RequestedRedirectUrl = redirectUrl;
                                request.RequestedRedirectUrl = model.RequestedRedirectUrl;
                            }
                            await this.authFlowCacheProvider.SetAuthFlowAsync(flow.Id, flow);
                        }
                        else if (requestParameters.RequestType == Constants.RequestTypes.WsFederationSignIn)
                        {
                            if (requestParameters.RequestMethod == Constants.RequestMethods.HttpPost)
                            {
                                model.RequestedPageContent = this.wsFederationHandler.GetWsFederationSignInHttpPostPageContent(request);
                            }
                            else
                            {
                                model.RequestedRedirectUrl = this.wsFederationHandler.GetWsFederationSignInHttpGetRedirectUrl(request);
                                request.RequestedRedirectUrl = model.RequestedRedirectUrl;
                            }
                            await this.authFlowCacheProvider.SetAuthFlowAsync(flow.Id, flow);
                        }

                        if (request.Response != null)
                        {
                            this.telemetryClient.TrackEvent("AuthResponse.Received", new Dictionary<string, string> { { "AuthFlowId", flow.Id }, { "RequestType", request.Parameters?.RequestType } }, new Dictionary<string, double> { { "TimeTakenMs", (request.Response.TimeCreated - request.TimeCreated).TotalMilliseconds } });
                        }
                        if (flow.IsComplete)
                        {
                            flow.TimeCompleted = DateTimeOffset.UtcNow;
                            this.telemetryClient.TrackEvent("AuthFlow.Completed", new Dictionary<string, string> { { "AuthFlowId", flow.Id }, { "RequestType", flow.RequestType } }, new Dictionary<string, double> { { "TimeTakenMs", (flow.TimeCompleted.Value - flow.TimeCreated).TotalMilliseconds } });
                            if (flow.IsComplete && !string.IsNullOrEmpty(flowReferenceToRemoveFromCacheWhenComplete))
                            {
                                await this.authFlowCacheProvider.RemoveAuthFlowAsync(flowReferenceToRemoveFromCacheWhenComplete);
                            }
                        }

                        // Set the response to the last relevant response received.
                        model.Response = flow.Requests.Last().Response;
                    }
                }
            }
            catch (Exception exc)
            {
                model.Response = AuthResponse.FromException(exc);
            }
            if (model.RequestParameters == null)
            {
                // Create new request parameters and set sensible defaults if not provided.
                model.RequestParameters = requestParameters ?? new AuthRequestParameters();
                if (string.IsNullOrWhiteSpace(model.RequestParameters.RequestType))
                {
                    model.RequestParameters.RequestType = model.RequestParameters.RequestType ?? Constants.RequestTypes.OpenIdConnect;
                    model.RequestParameters.ResponseType = model.RequestParameters.ResponseType ?? IdentityModel.OidcConstants.ResponseTypes.IdToken;
                    model.RequestParameters.Scope = model.RequestParameters.Scope ?? IdentityModel.OidcConstants.StandardScopes.OpenId;
                    model.RequestParameters.ResponseMode = model.RequestParameters.ResponseMode ?? IdentityModel.OidcConstants.ResponseModes.FormPost;
                    model.RequestParameters.RedirectUri = model.RequestParameters.RedirectUri ?? this.absoluteUrlProvider.GetAbsoluteRootUrl();
                    model.RequestParameters.RequestMethod = model.RequestParameters.RequestMethod ?? Constants.RequestMethods.HttpRedirect;
                }
            }
            return model;
        }

        #endregion
    }
}