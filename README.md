# Authr

## About

[Authr](https://www.authr.biz/) is a generic web application that you can use to test various authentication and authorization scenarios such as **OpenID Connect**, **OAuth 2.0**, **SAML 2.0** and **WS-Federation 1.2** - with any identity service that is compliant with these protocols.

You can simply start a new request using the parameters of your choice, and after the flow is complete you will see the full details and the final response(s) - decoded and interpreted whenever possible.

![Authr demo screen recording to request an ID token via OpenID Connect](media/Authr-OIDC-IdToken.gif)

You can also just use the token decoder directly if you have a JWT or SAML token and want to see the contents. Note that in that case the token is decoded on your device and will never leave your browser!

![Authr demo screen recording to decode JWT and SAML tokens](media/Authr-TokenDecoder.gif)

If you choose to create an account and sign in to Authr, you can also save the configuration details of your favorite identity services, client applications and even complete request templates for easier reuse later on.

![Authr demo screen recording to show signing in and using saved request templates](media/Authr-SignedIn.gif)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
