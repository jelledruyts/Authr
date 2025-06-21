using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Authr.WebApp.Infrastructure;
using Authr.WebApp.Models;
using Authr.WebApp.Services;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Cryptography;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace Authr.WebApp.Handlers
{
    public class Saml2Handler
    {
        #region Fields

        private readonly ILogger<Saml2Handler> logger;
        private readonly AbsoluteUrlProvider absoluteUrlProvider;
        private readonly ICertificateProvider certificateProvider;

        #endregion

        #region Constructors

        public Saml2Handler(ILogger<Saml2Handler> logger, AbsoluteUrlProvider absoluteUrlProvider, ICertificateProvider certificateProvider)
        {
            this.logger = logger;
            this.absoluteUrlProvider = absoluteUrlProvider;
            this.certificateProvider = certificateProvider;
        }

        #endregion

        #region IsConfigured

        public bool IsConfigured()
        {
            return this.certificateProvider.IsCertificateConfigured(Constants.CertificateNames.SigningCertificate) && this.certificateProvider.IsCertificateConfigured(Constants.CertificateNames.EncryptionCertificate);
        }

        #endregion

        #region Metadata

        public async Task<string> GetMetadataXmlAsync()
        {
            var samlConfiguration = await this.GetSamlConfigurationAsync();
            var entityDescriptor = new EntityDescriptor(samlConfiguration)
            {
                ValidUntil = 36500, // 100 years
                SPSsoDescriptor = new SPSsoDescriptor
                {
                    SigningCertificates = new[] { await this.certificateProvider.GetCertificateAsync(Constants.CertificateNames.SigningCertificate) },
                    EncryptionCertificates = new[] { await this.certificateProvider.GetCertificateAsync(Constants.CertificateNames.EncryptionCertificate) },
                    AuthnRequestsSigned = false, // Requests are only signed when requested, so in metadata we specify that they aren't signed by default.
                    AssertionConsumerServices = new[]
                    {
                        new AssertionConsumerService
                        {
                            Binding = ProtocolBindings.HttpPost,
                            Location = new Uri(this.absoluteUrlProvider.GetAbsoluteRootUrl())
                        },
                        new AssertionConsumerService
                        {
                            Binding = ProtocolBindings.HttpRedirect,
                            Location = new Uri(this.absoluteUrlProvider.GetAbsoluteRootUrl())
                        }
                    },
                    SingleLogoutServices = new[]
                    {
                        new SingleLogoutService
                        {
                            Binding = ProtocolBindings.HttpPost,
                            Location = new Uri(this.absoluteUrlProvider.GetAbsoluteRootUrl())
                        },
                        new SingleLogoutService
                        {
                            Binding = ProtocolBindings.HttpRedirect,
                            Location = new Uri(this.absoluteUrlProvider.GetAbsoluteRootUrl())
                        }
                    }
                }
            };
            var metadata = new Saml2Metadata(entityDescriptor);
            return metadata.CreateMetadata().ToXml();
        }

        #endregion

        #region Decrypt Token

        public async Task<string> DecryptTokenAsync(DecryptTokenRequest request)
        {
            var decryptionCertificate = await this.certificateProvider.GetCertificateAsync(Constants.CertificateNames.EncryptionCertificate);
            if (decryptionCertificate == null)
            {
                this.logger.LogWarning("A token decryption was requested but an encryption/decryption certificate wasn't configured.");
                return null;
            }
            var encryptedToken = request.EncryptedToken;
            if (string.IsNullOrWhiteSpace(encryptedToken))
            {
                return null;
            }
            try
            {
                if (encryptedToken.IndexOf('<') < 0)
                {
                    // The token doesn't look like XML, Base64 decode it first.
                    encryptedToken = Encoding.UTF8.GetString(Convert.FromBase64String(encryptedToken));
                }
                // Load the encrypted token as an XML document.
                var tokenXml = new XmlDocument();
                tokenXml.LoadXml(encryptedToken);

                // Decrypt the encrypted portion of the XML token.
                new Saml2EncryptedXml(tokenXml, decryptionCertificate.GetSamlRSAPrivateKey()).DecryptDocument();

                // Return as an indented XML string.
                using (var stringWriter = new StringWriter(new StringBuilder()))
                {
                    var xmlTextWriter = new XmlTextWriter(stringWriter) { Formatting = Formatting.Indented };
                    tokenXml.Save(xmlTextWriter);
                    return stringWriter.ToString();
                }
            }
            catch (Exception exc)
            {
                this.logger.LogWarning(exc, "Could not decrypt token: " + exc.Message);
                return null;
            }
        }

        #endregion

        #region Authentication

        public async Task<string> GetAuthenticationRequestHttpPostPageContentAsync(AuthRequest request)
        {
            var samlRequest = await GetSaml2AuthenticationRequestAsync(request);
            var binding = GetSaml2Binding<Saml2PostBinding>(request, samlRequest);
            return binding.PostContent;
        }

        public async Task<string> GetAuthenticationRequestHttpGetRedirectUrl(AuthRequest request)
        {
            var samlRequest = await GetSaml2AuthenticationRequestAsync(request);
            var binding = GetSaml2Binding<Saml2RedirectBinding>(request, samlRequest);
            return binding.RedirectLocation.ToString();
        }

        #endregion

        #region Logout

        public async Task<string> GetLogoutRequestHttpPostPageContentAsync(AuthRequest request)
        {
            var samlRequest = await GetSaml2LogoutRequestAsync(request);
            var binding = GetSaml2Binding<Saml2PostBinding>(request, samlRequest);
            return binding.PostContent;
        }

        public async Task<string> GetLogoutRequestHttpGetRedirectUrl(AuthRequest request)
        {
            var samlRequest = await GetSaml2LogoutRequestAsync(request);
            var binding = GetSaml2Binding<Saml2RedirectBinding>(request, samlRequest);
            return binding.RedirectLocation.ToString();
        }

        #endregion

        #region Helper Methods

        private async Task<Saml2Configuration> GetSamlConfigurationAsync()
        {
            return new Saml2Configuration
            {
                Issuer = this.absoluteUrlProvider.GetAbsoluteRootUrl(),
                SigningCertificate = await this.certificateProvider.GetCertificateAsync(Constants.CertificateNames.SigningCertificate),
                EncryptionCertificate = await this.certificateProvider.GetCertificateAsync(Constants.CertificateNames.EncryptionCertificate),
                DecryptionCertificate = await this.certificateProvider.GetCertificateAsync(Constants.CertificateNames.EncryptionCertificate)
            };
        }

        private async Task<Saml2AuthnRequest> GetSaml2AuthenticationRequestAsync(AuthRequest request)
        {
            Guard.NotEmpty(request.Parameters.SamlSignOnEndpoint, "The SAML sign-on endpoint must be specified for a SAML 2.0 Authentication Request.");
            Guard.NotEmpty(request.Parameters.RedirectUri, "The redirect uri must be specified for a SAML 2.0 Authentication Request.");
            Guard.NotEmpty(request.Parameters.SamlServiceProviderIdentifier, "The SAML service provider identifier must be specified for a SAML 2.0 Authentication Request.");

            // Set up the SAML configuration.
            var samlConfiguration = await GetSamlConfigurationAsync();
            samlConfiguration.SignAuthnRequest = request.Parameters.SignRequest;
            // Additional optional parameters that could be supported in the future:
            // samlConfiguration.SignatureAlgorithm = Saml2SecurityAlgorithms.RsaSha256Signature;

            // Set up the SAML authentication request.
            return new Saml2AuthnRequest(samlConfiguration)
            {
                IdAsString = "_" + request.FlowId, // Set the request's "ID" parameter to the flow id so it can be correlated when the response comes back.
                Destination = new Uri(request.Parameters.SamlSignOnEndpoint),
                AssertionConsumerServiceUrl = new Uri(request.Parameters.RedirectUri),
                Issuer = request.Parameters.SamlServiceProviderIdentifier,
                ForceAuthn = request.Parameters.ForceAuthentication,
                IsPassive = request.Parameters.SilentAuthentication
                // Additional optional parameters that could be supported in the future:
                // NameIdPolicy = new NameIdPolicy
                // {
                //     AllowCreate = true,
                //     Format = NameIdentifierFormats.Email.ToString(),
                //     SPNameQualifier = request.Parameters.SamlServiceProviderIdentifier
                // }
            };
        }

        private async Task<Saml2LogoutRequest> GetSaml2LogoutRequestAsync(AuthRequest request)
        {
            Guard.NotEmpty(request.Parameters.SamlLogoutEndpoint, "The SAML logout endpoint must be specified for a SAML 2.0 Logout Request.");
            Guard.NotEmpty(request.Parameters.SamlServiceProviderIdentifier, "The SAML service provider identifier must be specified for a SAML 2.0 Logout Request.");
            Guard.NotEmpty(request.Parameters.NameId, "The SAML NameId must be specified for a SAML 2.0 Logout Request.");

            // Set up the SAML configuration.
            var samlConfiguration = await GetSamlConfigurationAsync();

            // Set up the SAML logout request.
            return new Saml2LogoutRequest(samlConfiguration)
            {
                IdAsString = "_" + request.FlowId, // Set the request's "ID" parameter to the flow id so it can be correlated when the response comes back.
                Destination = new Uri(request.Parameters.SamlLogoutEndpoint),
                Issuer = request.Parameters.SamlServiceProviderIdentifier,
                NameId = new Saml2NameIdentifier(request.Parameters.NameId),
                SessionIndex = request.Parameters.SessionIndex
            };
        }

        private T GetSaml2Binding<T>(AuthRequest request, Saml2Request samlRequest) where T : Saml2Binding<T>, new()
        {
            var binding = new T();
            binding.RelayState = Constants.StatePrefixes.Flow + request.FlowId;
            binding.Bind(samlRequest);
            request.RequestMessage = binding.XmlDocument.OuterXml;
            return binding;
        }

        #endregion
    }
}