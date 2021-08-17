using System;
using System.Linq;
using System.Threading.Tasks;
using Authr.WebApp.Models;
using Authr.WebApp.Services;
using Microsoft.Extensions.Logging;

namespace Authr.WebApp.Handlers
{
    public class UserConfigurationHandler
    {
        #region Fields

        private readonly ILogger<UserConfigurationHandler> logger;
        private readonly IUserConfigurationProvider userConfigurationProvider;

        #endregion

        #region Constructors

        public UserConfigurationHandler(ILogger<UserConfigurationHandler> logger, IUserConfigurationProvider userConfigurationProvider)
        {
            this.logger = logger;
            this.userConfigurationProvider = userConfigurationProvider;
        }

        #endregion

        #region Get

        public Task<UserConfiguration> GetUserConfigurationAsync(string userId)
        {
            return this.userConfigurationProvider.GetUserConfigurationAsync(userId);
        }

        #endregion

        #region Save

        public async Task SaveAsync(UserConfiguration userConfiguration)
        {
            // Ensure IDs are always set.
            foreach (var requestTemplate in userConfiguration.RequestTemplates.Where(r => string.IsNullOrWhiteSpace(r.Id)))
            {
                requestTemplate.Id = Guid.NewGuid().ToString();
            }
            foreach (var identityService in userConfiguration.IdentityServices)
            {
                if (string.IsNullOrWhiteSpace(identityService.Id))
                {
                    identityService.Id = Guid.NewGuid().ToString();
                }
                foreach (var clientApplication in identityService.ClientApplications.Where(c => string.IsNullOrWhiteSpace(c.Id)))
                {
                    clientApplication.Id = Guid.NewGuid().ToString();
                }
            }

            await this.userConfigurationProvider.SaveUserConfigurationAsync(userConfiguration);
        }

        #endregion

        #region Update And Save

        public async Task<UserConfiguration> UpdateAndSaveAsync(string userId, ApiClientRequest request)
        {
            // Retrieve user configuration.
            var userConfiguration = await this.userConfigurationProvider.GetUserConfigurationAsync(userId);

            // Save the identity service.
            if (request.Options.SaveIdentityService && !string.IsNullOrWhiteSpace(request.Options.SaveIdentityServiceAsName))
            {
                // Add or update the identity service in user configuration.
                var identityService = MergeIdentityService(userConfiguration, request.Options.SaveIdentityServiceAsName, request.RequestParameters);

                // Update the request parameters to refer to the identity service.
                request.RequestParameters.IdentityServiceId = identityService.Id;
            }

            // Save the client app.
            if (request.Options.SaveClientApplication && !string.IsNullOrWhiteSpace(request.Options.SaveClientApplicationAsName))
            {
                var identityService = userConfiguration.IdentityServices.SingleOrDefault(i => string.Equals(i.Id, request.RequestParameters.IdentityServiceId, StringComparison.InvariantCultureIgnoreCase));
                if (identityService == null)
                {
                    this.logger.LogWarning("A request was made to save the client app but the related identity service was not defined.");
                }
                else
                {
                    // Add or update the client app in user configuration.
                    var clientApp = MergeClientApplication(userConfiguration, identityService, request.Options.SaveClientApplicationAsName, request.RequestParameters);

                    // Update the request parameters to refer to the client app.
                    request.RequestParameters.ClientApplicationId = clientApp.Id;
                }
            }

            // Save the request template.
            if (request.Options.SaveRequestTemplate && !string.IsNullOrWhiteSpace(request.Options.SaveRequestTemplateAsName))
            {
                // Add or update the client app in user configuration.
                var requestTemplate = MergeRequestTemplate(userConfiguration, request.Options.SaveRequestTemplateAsName, request.RequestParameters);
            }

            await this.userConfigurationProvider.SaveUserConfigurationAsync(userConfiguration);
            return userConfiguration;
        }

        #endregion

        #region Helper Methods

        private IdentityService MergeIdentityService(UserConfiguration userConfiguration, string identityServiceName, AuthRequestParameters requestParameters)
        {
            var identityService = userConfiguration.IdentityServices.SingleOrDefault(i => string.Equals(i.Name, identityServiceName, StringComparison.InvariantCultureIgnoreCase));
            if (identityService != null)
            {
                this.logger.LogInformation($"Updating identity service \"{identityServiceName}\" for user \"{userConfiguration.UserId}\".");
                identityService.Update(requestParameters);
            }
            else
            {
                this.logger.LogInformation($"Adding identity service \"{identityServiceName}\" for user \"{userConfiguration.UserId}\".");
                identityService = IdentityService.FromRequestParameters(identityServiceName, requestParameters);
                userConfiguration.IdentityServices.Add(identityService);
            }
            return identityService;
        }

        private ClientApplication MergeClientApplication(UserConfiguration userConfiguration, IdentityService identityService, string clientApplicationName, AuthRequestParameters requestParameters)
        {
            var clientApplication = identityService.ClientApplications.SingleOrDefault(a => string.Equals(a.Name, clientApplicationName, StringComparison.InvariantCultureIgnoreCase));
            if (clientApplication != null)
            {
                this.logger.LogInformation($"Updating client application \"{clientApplicationName}\" for user \"{userConfiguration.UserId}\".");
                clientApplication.Update(requestParameters);
            }
            else
            {
                this.logger.LogInformation($"Adding client application \"{clientApplicationName}\" for user \"{userConfiguration.UserId}\".");
                clientApplication = ClientApplication.FromRequestParameters(clientApplicationName, requestParameters);
                identityService.ClientApplications.Add(clientApplication);
            }
            return clientApplication;
        }

        private AuthRequestTemplate MergeRequestTemplate(UserConfiguration userConfiguration, string requestTemplateName, AuthRequestParameters requestParameters)
        {
            var requestTemplate = userConfiguration.RequestTemplates.SingleOrDefault(r => string.Equals(r.Name, requestTemplateName, StringComparison.InvariantCultureIgnoreCase));
            if (requestTemplate != null)
            {
                this.logger.LogInformation($"Updating request template \"{requestTemplateName}\" for user \"{userConfiguration.UserId}\".");
                requestTemplate.Update(requestParameters);
            }
            else
            {
                this.logger.LogInformation($"Adding request template \"{requestTemplateName}\" for user \"{userConfiguration.UserId}\".");
                requestTemplate = AuthRequestTemplate.FromRequestParameters(requestTemplateName, requestParameters);
                userConfiguration.RequestTemplates.Add(requestTemplate);
            }
            return requestTemplate;
        }

        #endregion
    }
}