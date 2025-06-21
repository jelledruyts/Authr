new Vue({
    el: '#app',
    data: function () {
        return {
            requestParameters: null,
            response: null,
            flow: null,
            userConfiguration: null,
            generatedLink: null,
            requestOptions: {
                saveIdentityService: false,
                saveIdentityServiceAsName: null,
                saveClientApplication: false,
                saveClientApplicationAsName: null,
                saveRequestTemplate: false,
                saveRequestTemplateAsName: null
            },
            requestTemplateId: null,
            selectedIdentityService: null,
            identityServiceImportRequestParameters: { importType: 'Metadata' },
            processing: false,
            validationMessage: null,
            errorMessage: null
        }
    },
    computed: {
        userSignedIn: function () {
            return this.userConfiguration !== null;
        }
    },
    filters: {
        datetime: function (value) {
            if (value == null) {
                return null;
            }
            return new Date(value).toLocaleString();
        },
        token: function (decodedToken) {
            return Authr.formatDecodedToken(decodedToken);
        },
        trimParameters: function (value) {
            // Remove all null properties from the object.
            if (value && typeof value === 'object') {
                return Object.keys(value).reduce(function (result, key) {
                    if (key !== 'httpRequestLog' && key !== 'httpResponseLog' && key !== 'timeCreated' && value[key] !== null && value[key] !== undefined) {
                        result[key] = value[key];
                    }
                    return result;
                }, {});
            }
        }
    },
    watch: {
        'response': function (newValue, oldValue) {
            if (this.response) {
                this.showTab('mainTabHeaderResponse');
            }
        },
        'requestTemplateId': function (newValue, oldValue) {
            if (this.userConfiguration) {
                var requestTemplate = this.findById(this.userConfiguration.requestTemplates, newValue);
                if (requestTemplate !== null) {
                    // Set the request parameters to a clone of the template's request parameters.
                    this.requestParameters = JSON.parse(JSON.stringify(requestTemplate.requestParameters));
                    this.requestOptions.saveRequestTemplateAsName = requestTemplate.name;
                } else {
                    this.requestOptions.saveRequestTemplateAsName = null;
                }
            }
        },
        'requestParameters.grantType': function (newValue, oldValue) {
            this.validateParameters();
        },
        'requestParameters.requestType': function (newValue, oldValue) {
            this.validateParameters();
        },
        'requestParameters.scope': function (newValue, oldValue) {
            this.validateParameters();
        },
        'requestParameters.responseMode': function (newValue, oldValue) {
            this.validateParameters();
        },
        'requestParameters.responseType': function (newValue, oldValue) {
            this.validateParameters();
        },
        'requestParameters.identityServiceId': function (newValue, oldValue) {
            if (this.userConfiguration) {
                var identityService = this.findById(this.userConfiguration.identityServices, newValue);
                if (identityService !== null) {
                    this.copyIdentityServiceProperties(identityService, this.requestParameters);
                    this.requestOptions.saveIdentityServiceAsName = identityService.name;

                    // Check if the current client application is part of the current identity service.
                    var clientApplication = this.findById(identityService.clientApplications, this.requestParameters.clientApplicationId);
                    if (clientApplication === null || clientApplication.id !== this.requestParameters.clientApplicationId) {
                        // If not, ensure no client application is set.
                        this.requestParameters.clientApplicationId = null;
                    }
                } else {
                    // There is no identity service, also ensure no client application is set.
                    this.requestParameters.clientApplicationId = null;
                    this.requestOptions.saveIdentityServiceAsName = null;
                }
                this.selectedIdentityService = identityService;
            }
        },
        'requestParameters.clientApplicationId': function (newValue, oldValue) {
            this.requestOptions.saveClientApplicationAsName = null;
            if (this.selectedIdentityService !== null) {
                var clientApplication = this.findById(this.selectedIdentityService.clientApplications, newValue);
                if (clientApplication !== null) {
                    this.requestParameters.clientId = clientApplication.clientId;
                    this.requestParameters.clientSecret = clientApplication.clientSecret;
                    this.requestOptions.saveClientApplicationAsName = clientApplication.name;
                }
            }
        }
    },
    methods: {
        showTab: function (tabHeaderId) {
            setTimeout(function () {
                // This is executed after Vue rendering is complete; trigger a call to show the tab.
                bootstrap.Tab.getOrCreateInstance('#' + tabHeaderId).show();
                // Scroll to the top already (the tab is showing asynchronously so that's not complete yet).
                document.getElementById('mainTabHeader').scrollIntoView();
            }, 0);
        },
        findById: function (array, id) {
            if (array) {
                for (var i = 0; i < array.length; i++) {
                    if (array[i].id === id) {
                        return array[i];
                    }
                }
            }
            return null;
        },
        copyIdentityServiceProperties: function (from, to) {
            to.authorizationEndpoint = from.authorizationEndpoint;
            to.tokenEndpoint = from.tokenEndpoint;
            to.deviceCodeEndpoint = from.deviceCodeEndpoint;
            to.samlSignOnEndpoint = from.samlSignOnEndpoint;
            to.samlLogoutEndpoint = from.samlLogoutEndpoint;
            to.wsFederationSignOnEndpoint = from.wsFederationSignOnEndpoint;
        },
        validateParameters: function () {
            this.validationMessage = '';
            if (this.requestParameters.requestType === 'OAuth2CustomGrant') {
                if (this.requestParameters.grantType === null || this.requestParameters.grantType.trim() === '') {
                    this.validationMessage += 'The grant type must be specified for an OAuth 2.0 custom grant. ';
                }
            }
            if (this.requestParameters.requestType === 'OpenIdConnect') {
                // Make sure 'openid' is part of the requested scopes (https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest).
                if (this.requestParameters.scope === null || (' ' + this.requestParameters.scope + ' ').indexOf('openid') < 0) {
                    this.validationMessage += 'The scope must include "openid" for an OpenID Connect request. ';
                }
            }
            if (this.requestParameters.requestType === 'Implicit') {
                // Make sure response mode is not set and response type is set to 'token' (https://tools.ietf.org/html/rfc6749#section-4.2.1).
                if (this.requestParameters.responseType !== 'token') {
                    this.validationMessage += 'The response type should be set to "token" for an OAuth 2.0 Implicit Grant request. ';
                }
                if (this.requestParameters.responseMode) {
                    this.validationMessage += 'The response mode should not be set for an OAuth 2.0 Implicit Grant request. ';
                }
            }
            if (this.requestParameters.requestType === 'AuthorizationCode') {
                // Make sure response mode is not set and response type is set to 'code' (https://tools.ietf.org/html/rfc6749#section-3.1.1).
                if (this.requestParameters.responseType !== 'code') {
                    this.validationMessage += 'The response type should be set to "code" for an OAuth 2.0 Authorization Code request. ';
                }
                if (this.requestParameters.responseMode) {
                    this.validationMessage += 'The response mode should not be set for an OAuth 2.0 Authorization Code request. ';
                }
            }
        },
        prepareDeviceTokenRequestParameters: function (deviceCode) {
            this.requestParameters.requestType = 'DeviceToken';
            this.requestParameters.deviceCode = deviceCode;
            this.showTab('mainTabHeaderRequest');
        },
        prepareRefreshTokenRequestParameters: function (refreshToken) {
            this.requestParameters.requestType = 'RefreshToken';
            this.requestParameters.refreshToken = refreshToken;
            this.showTab('mainTabHeaderRequest');
        },
        submitRequest: function (requestAction) {
            var requestValue = {
                requestParameters: this.requestParameters,
                options: this.requestOptions
            };
            requestValue.requestParameters.requestAction = requestAction;
            this.submit('request', requestValue);
        },
        submitResponse: function (response) {
            this.submit('response', response);
        },
        submit: function (path, value) {
            this.response = null;
            this.flow = null;
            this.processing = true;
            this.errorMessage = null;
            var that = this;
            axios.post('/api/' + path, value)
                .then(function (response) {
                    // Make sure to also set the requestParameters coming back, e.g. to get the request parameter details
                    // for a previous request that was now responded to through a URL #fragment (e.g. implicit flow).
                    that.requestParameters = response.data.requestParameters;
                    that.response = response.data.response;
                    if (response.data.userConfiguration) {
                        that.userConfiguration = response.data.userConfiguration;
                    }
                    that.flow = response.data.flow;
                    that.requestOptions.saveIdentityService = false;
                    that.requestOptions.saveClientApplication = false;
                    that.requestOptions.saveRequestTemplate = false;
                    that.generatedLink = response.data.generatedLink;
                    if (response.data.requestedRedirectUrl) {
                        window.location.replace(response.data.requestedRedirectUrl);
                    } else if (response.data.requestedPageContent) {
                        document.open();
                        document.write(response.data.requestedPageContent);
                        document.close();
                    } else {
                        that.processing = false;
                    }
                })
                .catch(function (error) {
                    console.log(error);
                    that.errorMessage = error.message;
                    Authr.showToast(error.message);
                    that.processing = false;
                });
        },
        sendToTokenDecoder: function (token) {
            var url = 'token#token=' + encodeURIComponent(token);
            window.open(url, '_blank').focus();
        },
        decodeToken: function (token) {
            return Authr.decodeToken(token);
        },
        showIdentityServiceImportDialog: function () {
            bootstrap.Modal.getOrCreateInstance('#importIdentityService-modal').show();
        },
        performIdentityServiceImport: function () {
            this.processing = true;
            this.errorMessage = null;
            var that = this;
            axios.post('/api/identityServiceImportRequest', this.identityServiceImportRequestParameters)
                .then(function (response) {
                    var identityService = response.data;
                    if (identityService) {
                        that.copyIdentityServiceProperties(identityService, that.requestParameters);
                    }
                    bootstrap.Modal.getOrCreateInstance('#importIdentityService-modal').hide();
                    that.processing = false;
                })
                .catch(function (error) {
                    console.log(error);
                    that.errorMessage = error.message;
                    Authr.showToast(error.message);
                    that.processing = false;
                });
        }
    },
    created: function () {
        this.requestParameters = globalRequestParameters;
        this.response = globalResponse;
        this.flow = globalFlow;
        this.userConfiguration = globalUserConfiguration;
        this.generatedLink = globalGeneratedLink;
        if (location.hash && location.hash.length > 1) {
            // If there are parameters in the #fragment of the URL, this is likely an external auth response;
            // send it to the back-end API for processing.
            var urlFragment = {};
            window.location.hash.substring(1).split('&').map(function (item) {
                if (item.indexOf('=') >= 0) {
                    var key = decodeURIComponent(item.split('=')[0]).replace(/\+/g, ' ');
                    var value = decodeURIComponent(item.split('=')[1]).replace(/\+/g, ' ');
                    urlFragment[key] = value;
                }
            });
            this.submitResponse(urlFragment);
        }
    }
});