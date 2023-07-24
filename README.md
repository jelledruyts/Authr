# Authr

## About

[Authr](https://authr.dev/) is a generic web application that you can use to test various authentication and authorization scenarios such as **OpenID Connect**, **OAuth 2.0**, **SAML 2.0** and **WS-Federation 1.2** - with any identity service that is compliant with these protocols.

You can simply start a new request using the parameters of your choice, and after the flow is complete you will see the full details and the final response(s) - decoded and interpreted whenever possible.

![Authr demo screen recording to request an ID token via OpenID Connect](media/Authr-OIDC-IdToken.gif)

You can also just use the token decoder directly if you have a JWT or SAML token and want to see the contents. Note that in that case the token is decoded on your device and will never leave your browser!

![Authr demo screen recording to decode JWT and SAML tokens](media/Authr-TokenDecoder.gif)

If you choose to create an account and sign in to Authr, you can also save the configuration details of your favorite identity services, client applications and even complete request templates for easier reuse later on.

![Authr demo screen recording to show signing in and using saved request templates](media/Authr-SignedIn.gif)

## Self-Host

Instead of using the public [Authr](https://authr.dev/) website, you can also deploy it to Azure App Service directly:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjelledruyts%2FAuthr%2Fmaster%2Fazuredeploy-webapp.json)

You can also deploy Authr as a container to a web hosting service of your choice. You can find the latest published version of the Docker container publicly on the **GitHub packages container registry** at **[ghcr.io/jelledruyts/authr](https://ghcr.io/jelledruyts/authr)** with image tag `jelledruyts/authr:latest` or simply `jelledruyts/authr`.

The app can be configured with the configuration settings below (using environment variables, use a double underscore instead of `:` if needed, for example `App__AuthFlowCache__ConnectionString`). All connection strings for Azure storage mentioned below can refer to the same storage account; a different container is used for each configuration setting.

| Setting | Purpose |
| ------- | ------- |
| `App:AuthFlowCache:ConnectionString` | (Optional) Connection string to an Azure storage account to be used for caching temporary flow correlation data; if not configured, this will use an in-memory cache. |
| `App:DataProtection:ConnectionString` | (Optional) Connection string to an Azure storage account to be used for [ASP.NET Core data protection](https://learn.microsoft.com/aspnet/core/security/data-protection/introduction?view=aspnetcore-7.0). |
| `ApplicationInsights:InstrumentationKey` | (Optional) Instrumentation key to be used for sending usage telemetry to [Application Insights](https://learn.microsoft.com/azure/azure-monitor/app/app-insights-overview). |

If you want to support SAML 2.0, you must provide a signing and encryption certificate and configure the following additional settings:

| Setting | Purpose |
| ------- | ------- |
| `App:Certificates:ConnectionString` | Connection string to an Azure storage account where the SAML certificates are stored. |
| `App:Certificates:SigningCertificate:Path` | The path to the SAML signing certificate, stored in PFX format inside the `certificates` container in the storage account. |
| `App:Certificates:SigningCertificate:Password` | The password for the SAML signing certificate PFX file. |
| `App:Certificates:EncryptionCertificate:Path` | The path to the SAML encryption certificate, stored in PFX format inside the `certificates` container in the storage account. |
| `App:Certificates:EncryptionCertificate:Password` | The password for the SAML encryption certificate PFX file. |

If you want to allow users to sign in and save their configuration, create an [Azure AD B2C tenant](https://learn.microsoft.com/azure/active-directory-b2c/tutorial-create-tenant) and configure the following additional settings:

| Setting | Purpose |
| ------- | ------- |
| `AzureAdB2C:Instance` | The tenant instance, for example `https://authr.b2clogin.com/tfp/`. |
| `AzureAdB2C:ClientId` | The client ID of the app registration. |
| `AzureAdB2C:Domain` | The tenant domain, for example `authr.onmicrosoft.com`. |
| `AzureAdB2C:SignUpSignInPolicyId` | The policy used for sign up and sign in, for example `B2C_1_SignUpOrIn`. |
| `AzureAdB2C:ResetPasswordPolicyId` | The policy used for password reset, for example `B2C_1_ResetPassword`. |
| `AzureAdB2C:EditProfilePolicyId` | The policy used for profile editing, for example `B2C_1_EditProfile`. |
| `App:UserConfiguration:ConnectionString` | Connection string to an Azure storage account to be used for storing user configuration. |

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
