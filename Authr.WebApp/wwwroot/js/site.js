(function (Authr, undefined) {
    // Private methods and properties.
    var wellKnownClaims = {};
    addClaimInfo(wellKnownClaims, 'at_hash', 'Access Token Hash', 'A hash of the OAuth 2.0 Access Token.', null);
    addClaimInfo(wellKnownClaims, 'acct', 'Account Status', 'The account status of the user in the tenant that issued the token. If the user is a member of the tenant, the value is "0". If they are a guest, the value is "1".', null);
    addClaimInfo(wellKnownClaims, 'address', 'Address', 'The preferred postal address of the \'user\'.', null);
    addClaimInfo(wellKnownClaims, 'altsecid', 'Alternate Security ID', 'An alternate ID that allows users to have multiple social accounts tied to their local user account.', null);
    addClaimInfo(wellKnownClaims, 'app_displayname', 'App Display Name', 'The display name of the client application.', null);
    addClaimInfo(wellKnownClaims, 'appidacr', 'Application Authentication Context Class Reference', 'The authentication mechanism used by the application. For a public client, this is "0". If client ID and client secret were used, this is "1". If a client certificate was used, this is "2".', null);
    addClaimInfo(wellKnownClaims, 'azpacr', 'Application Authentication Context Class Reference', 'The authentication mechanism used by the application. For a public client, this is "0". If client ID and client secret were used, this is "1". If a client certificate was used, this is "2".', null);
    addClaimInfo(wellKnownClaims, 'appid', 'Application ID', 'The application ID of the client that is using the token to access a resource (either on behalf of itself or a user).', null);
    addClaimInfo(wellKnownClaims, 'aud', 'Audience', 'The audience of the targeted application, i.e. the intended recipient of the token.', null);
    addClaimInfo(wellKnownClaims, 'acr', 'Authentication Context Class Reference', 'The Authentication Context Class values that the authentication performed satisfied, implying a Level Of Assurance.', null);
    addClaimInfo(wellKnownClaims, 'http://schemas.microsoft.com/claims/authnclassreference', 'Authentication Context Class Reference', 'The Authentication Context Class values that the authentication performed satisfied, implying a Level Of Assurance.', null);
    addClaimInfo(wellKnownClaims, 'amr', 'Authentication Methods References', 'The authentication methods used by the user during authentication, e.g. a password or OTP.', null);
    addClaimInfo(wellKnownClaims, 'http://schemas.microsoft.com/claims/authnmethodsreferences', 'Authentication Methods References', 'The authentication methods used by the user during authentication, e.g. a password or OTP.', null);
    addClaimInfo(wellKnownClaims, 'auth_time', 'Authentication Time', 'The time the user has performed the actual authentication.', 'UnixTime');
    addClaimInfo(wellKnownClaims, 'http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant', 'Authentication Time', 'The time the user has performed the actual authentication.', 'UnixTime');
    addClaimInfo(wellKnownClaims, 'c_hash', 'Authorization Code Hash', 'A hash of the OAuth 2.0 Authorization Code that was used to redeem this token.', null);
    addClaimInfo(wellKnownClaims, 'azp', 'Authorized Party', 'The party to which the ID Token was issued.', null);
    addClaimInfo(wellKnownClaims, 'birthdate', 'Birthday', 'The birthday of the user.', null);
    addClaimInfo(wellKnownClaims, 'city', 'City', 'The city in which the user is located.', null);
    addClaimInfo(wellKnownClaims, 'country', 'Country', 'The country in which the user is located.', null);
    addClaimInfo(wellKnownClaims, 'platf', 'Device Platform', 'Restricted to managed devices that can verify the device type.', null);
    addClaimInfo(wellKnownClaims, 'http://schemas.microsoft.com/identity/claims/displayname', 'Display Name', 'The display name of the user.', null);
    addClaimInfo(wellKnownClaims, 'email', 'Email Address', 'The email address of the user.', null);
    addClaimInfo(wellKnownClaims, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', 'Email Address', 'The email address of the user.', null);
    addClaimInfo(wellKnownClaims, 'emails', 'Email Addresses', 'The email addresses of the user.', null);
    addClaimInfo(wellKnownClaims, 'email_verified', 'Email Verified', 'Indicates if the user\'s email address has been verified.', null);
    addClaimInfo(wellKnownClaims, 'exp', 'Expiration', 'The time after which the token cannot be used anymore.', 'UnixTime');
    addClaimInfo(wellKnownClaims, 'family_name', 'Family Name', 'The surname or last name of the user.', null);
    addClaimInfo(wellKnownClaims, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname', 'Family Name', 'The surname or last name of the user.', null);
    addClaimInfo(wellKnownClaims, 'gender', 'Gender', 'The gender of the user.', null);
    addClaimInfo(wellKnownClaims, 'given_name', 'Given Name', 'The given name or first name of the user.', null);
    addClaimInfo(wellKnownClaims, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname', 'Given Name', 'The given name or first name of the user.', null);
    addClaimInfo(wellKnownClaims, 'groups', 'Groups', 'The group memberships of the user.', null);
    addClaimInfo(wellKnownClaims, 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups', 'Groups', 'The group memberships of the user.', null);
    addClaimInfo(wellKnownClaims, 'hasgroups', 'Has Groups', 'Indicates if the user has at least one group membership.', null);
    addClaimInfo(wellKnownClaims, 'hd', 'Hosted Domain', 'The hosted G Suite domain of the user.', null);
    addClaimInfo(wellKnownClaims, 'http://schemas.microsoft.com/identity/claims/identityprovider', 'Identity Provider', 'The Identity Provider that authenticated the subject of the token, if that is different from the issuer of the token.', null);
    addClaimInfo(wellKnownClaims, 'idp', 'Identity Provider', 'The Identity Provider that authenticated the subject of the token, if that is different from the issuer of the token.', null);
    addClaimInfo(wellKnownClaims, 'in_corp', 'In Corp', 'Indicates if the user is authenticating from a corporate network.', null);
    addClaimInfo(wellKnownClaims, 'aio', 'Internal', 'An internal claim used by Microsoft Entra ID. Should be ignored.', null);
    addClaimInfo(wellKnownClaims, 'rh', 'Internal', 'An internal claim used by Microsoft Entra ID. Should be ignored.', null);
    addClaimInfo(wellKnownClaims, 'uti', 'Internal', 'An internal claim used by Microsoft Entra ID. Should be ignored.', null);
    addClaimInfo(wellKnownClaims, 'xms_st', 'Internal', 'An internal claim used by Microsoft Entra ID. Should be ignored.', null);
    addClaimInfo(wellKnownClaims, 'xms_tcdt', 'Internal', 'An internal claim used by Microsoft Entra ID. Should be ignored.', 'UnixTime');
    addClaimInfo(wellKnownClaims, 'ipaddr', 'IP Address', 'The IP address the user authenticated from.', null);
    addClaimInfo(wellKnownClaims, 'iat', 'Issued At', 'The time the token was issued.', 'UnixTime');
    addClaimInfo(wellKnownClaims, 'iss', 'Issuer', 'The issuer, i.e. the Security Token Service that issued the token.', null);
    addClaimInfo(wellKnownClaims, 'jobTitle', 'Job Title', 'The job title of the user.', null);
    addClaimInfo(wellKnownClaims, 'jti', 'JWT ID', 'A unique identifier for the token.', null);
    addClaimInfo(wellKnownClaims, 'locale', 'Locale', 'The locale of the user.', null);
    addClaimInfo(wellKnownClaims, 'middle_name', 'Middle Name', 'The middle name of the user.', null);
    addClaimInfo(wellKnownClaims, 'newUser', 'New User', 'Indicates if the user was registered as a new user during the authentication request that generated the token.', null);
    addClaimInfo(wellKnownClaims, 'nickname', 'Nickname', 'The nickname of the user.', null);
    addClaimInfo(wellKnownClaims, 'nonce', 'Nonce', 'The nonce value used to validate the token response.', null);
    addClaimInfo(wellKnownClaims, 'nbf', 'Not Before', 'The time before which the token cannot be used.', 'UnixTime');
    addClaimInfo(wellKnownClaims, 'http://schemas.microsoft.com/identity/claims/objectidentifier', 'Object ID', 'The unique and immutable object identifier of the user, which is always the same identifier even across different applications.', null);
    addClaimInfo(wellKnownClaims, 'oid', 'Object ID', 'The unique and immutable object identifier of the user, which is always the same identifier even across different applications.', null);
    addClaimInfo(wellKnownClaims, 'onprem_sid', 'On-Prem SID', 'The Security Identifier (SID) of the user in an on-premises authentication system.', null);
    addClaimInfo(wellKnownClaims, 'puid', 'Passport Unique ID', 'The unique identifier of the user in the Microsoft Passport system.', null);
    addClaimInfo(wellKnownClaims, 'pwd_exp', 'Password Expiration', 'The time the subject\'s password expires.', 'UnixTime');
    addClaimInfo(wellKnownClaims, 'pwd_url', 'Password URL', 'The URL where the user can reset their password.', null);
    addClaimInfo(wellKnownClaims, 'phone_number', 'Phone Number', 'The preferred telephone number of the user.', null);
    addClaimInfo(wellKnownClaims, 'phone_number_verified', 'Phone Number Verified', 'Indicates if the user\'s phone number has been verified.', null);
    addClaimInfo(wellKnownClaims, 'picture', 'Picture', 'The URL of the profile picture of the user.', null);
    addClaimInfo(wellKnownClaims, 'postalCode', 'Postal Code', 'The postal code of the user\'s address.', null);
    addClaimInfo(wellKnownClaims, 'preferred_name', 'Preferred Name', 'The primary username that the user should be represented as.', null);
    addClaimInfo(wellKnownClaims, 'preferred_username', 'Preferred Username', 'The primary username that the user should be represented as.', null);
    addClaimInfo(wellKnownClaims, 'profile', 'Profile', 'The URL of the profile page of the user.', null);
    addClaimInfo(wellKnownClaims, 'roles', 'Roles', 'The roles that are assigned to the user for the application.', null);
    addClaimInfo(wellKnownClaims, 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role', 'Role', 'The role that is assigned to the user for the application.', null);
    addClaimInfo(wellKnownClaims, 'http://schemas.microsoft.com/identity/claims/scope', 'Scopes', 'The scopes, i.e. the permissions granted to the client application to act on behalf of the user.', null);
    addClaimInfo(wellKnownClaims, 'scp', 'Scopes', 'The scopes, i.e. the permissions granted to the client application to act on behalf of the user.', null);
    addClaimInfo(wellKnownClaims, 'signin_state', 'Sign-In State', 'The sign-in state of the user.', null);
    addClaimInfo(wellKnownClaims, 'state', 'State', 'The state or province in which the user is located.', null);
    addClaimInfo(wellKnownClaims, 'streetAddress', 'Street Address', 'The street address where the user is located.', null);
    addClaimInfo(wellKnownClaims, 'sub', 'Subject', 'The subject, i.e. the principal about which the token asserts information, such as the user of an application; this can have a different value for the same user depending on the application.', null);
    addClaimInfo(wellKnownClaims, 'name', 'Subject Name', 'A human-readable value that identifies the user in its fullest form.', null);
    addClaimInfo(wellKnownClaims, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', 'Subject Name', 'A human-readable value that identifies the user in its fullest form.', null);
    addClaimInfo(wellKnownClaims, 'http://schemas.microsoft.com/identity/claims/tenantid', 'Tenant ID', 'The identifier of the tenant in the Security Token Service that is the home realm of the user.', null);
    addClaimInfo(wellKnownClaims, 'tid', 'Tenant ID', 'The identifier of the tenant in the Security Token Service that is the home realm of the user.', null);
    addClaimInfo(wellKnownClaims, 'wids', 'Tenant-Wide Roles', 'Denotes the tenant-wide roles assigned to the user, as an array of RoleTemplateID GUIDs.', null);
    addClaimInfo(wellKnownClaims, 'http://schemas.microsoft.com/ws/2008/06/identity/claims/wids', 'Tenant-Wide Roles', 'Denotes the tenant-wide roles assigned to the user, as an array of RoleTemplateID GUIDs.', null);
    addClaimInfo(wellKnownClaims, 'tfp', 'Trust Framework Policy', 'The Trust Framework Policy, i.e. the user flow (policy) through which the user authenticated in Azure AD B2C.', null);
    addClaimInfo(wellKnownClaims, 'unique_name', 'Unique Name', 'A human-readable value that identifies the subject of the token.', null);
    addClaimInfo(wellKnownClaims, 'updated_at', 'Updated At', 'The time the user\'s information was last updated.', 'UnixTime');
    addClaimInfo(wellKnownClaims, 'http://schemas.microsoft.com/identity/claims/userprincipalname', 'User Principal Name', 'The User Principal Name (UPN) of the user.', null);
    addClaimInfo(wellKnownClaims, 'upn', 'User Principal Name', 'The User Principal Name (UPN) of the user.', null);
    addClaimInfo(wellKnownClaims, 'ver', 'Version', 'The version of the token format.', null);
    addClaimInfo(wellKnownClaims, 'website', 'Website', 'The URL of the user\'s web page.', null);
    addClaimInfo(wellKnownClaims, 'zoneinfo', 'Zone Info', 'The time zone where the user is located.', null);

    function addClaimInfo(bag, claimType, displayName, description, dataType) {
        bag[claimType] = {
            claimType: claimType,
            displayName: displayName,
            description: description,
            dataType: dataType || 'string'
        };
    }

    function tryDecodeJwt(value) {
        // A JWT always starts with 'e' and should have at least 1 '.' character (to separate header from body).
        if (value && value.startsWith('e') && value.indexOf('.') >= 0) {
            var jwtParts = value.split('.');
            if (jwtParts.length > 1) {
                var signature = null;
                if (jwtParts.length > 2) {
                    signature = jwtParts[2];
                }
                return {
                    tokenType: 'JWT',
                    header: tryDecodeJwtPart(jwtParts[0]),
                    body: tryDecodeJwtPart(jwtParts[1]),
                    signature: signature
                };
            }
        }
        return null;
    };

    function tryDecodeJwtPart(value) {
        try {
            var jwtPartBase64 = value.replace(/-/g, '+').replace(/_/g, '/');
            var jwtPartJson = decodeURIComponent(atob(jwtPartBase64).split('').map(function (c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));
            return JSON.parse(jwtPartJson);
        } catch (e) {
            return null;
        }
    };

    // https://stackoverflow.com/questions/376373/pretty-printing-xml-with-javascript/
    function formatXml(xml, tab) { // tab = optional indent value, default is tab (\t)
        var formatted = '', indent = '';
        tab = tab || '\t';
        xml.split(/>\s*</).forEach(function (node) {
            if (node.match(/^\/\w/)) indent = indent.substring(tab.length); // decrease indent by one 'tab'
            formatted += indent + '<' + node + '>\r\n';
            if (node.match(/^<?\w[^>]*[^\/]$/)) indent += tab; // increase indent
        });
        return formatted.substring(1, formatted.length - 3);
    }

    function stringToByteArray(value) {
        var array = new (window.Uint8Array !== void 0 ? Uint8Array : Array)(value.length);
        for (var i = 0, il = value.length; i < value.length; ++i) {
            array[i] = value.charCodeAt(i) & 0xff;
        }
        return array;
    }

    function utf8ToString(uintArray) {
        var encodedString = String.fromCharCode.apply(null, uintArray);
        return decodeURIComponent(escape(encodedString));
    }

    function tryDecodeSamlResponse(value) {
        try {
            var xml = value;
            if (!xml.startsWith('<')) {
                // The token isn't XML yet, try to base 64 decode (in case of a SAML POST binding).
                try {
                    var base64Value = value.replace(/-/g, '+').replace(/_/g, '/'); // Change invalid characters from Base64URL encoding into standard Base64 encoding values (i.e. replace '-' with '+' and '_' with '/').
                    xml = atob(base64Value);
                }
                catch (e) {
                    console.log('Error base 64 decoding value while attempting to decode SAML response: ' + e);
                }
            }
            if (!xml.startsWith('<')) {
                // The token isn't XML yet, try to URI decode, base 64 decode and inflate (in case of a SAML Redirect binding).
                try {
                    var base64Value = decodeURIComponent(value);
                    base64Value = base64Value.replace(/-/g, '+').replace(/_/g, '/'); // Change invalid characters from Base64URL encoding into standard Base64 encoding values (i.e. replace '-' with '+' and '_' with '/').
                    var inflate = new Zlib.RawInflate(stringToByteArray(atob(base64Value)));
                    var decompressed = inflate.decompress();
                    xml = utf8ToString(decompressed);
                }
                catch (e) {
                    console.log('Error inflating value while attempting to decode SAML response: ' + e);
                }
            }
            if (xml.startsWith('<')) {
                try {
                    xml = formatXml(xml, '  ');
                }
                catch (e) {
                    console.log('Error formatting XML: ' + e);
                }
                return {
                    tokenType: 'SAML',
                    header: null,
                    body: xml,
                    signature: null
                };
            }
        } catch (e) {
            return null;
        }
    };

    function getClaimInfo(claimType, claimValue) {
        var interpretedValue = null;
        var claimInfo = wellKnownClaims[claimType];
        if (claimInfo && claimInfo.dataType) {
            if (claimInfo.dataType === 'UnixTime' && typeof claimValue === 'number') {
                var dateValue = new Date(0); // The zero value sets the date instance to the Unix time epoch.
                dateValue.setUTCSeconds(claimValue);
                interpretedValue = dateValue.toLocaleString() + ' (local time)';
            }
        }
        return {
            claimType: claimType,
            value: claimValue,
            interpretedValue: interpretedValue,
            displayName: claimInfo ? claimInfo.displayName : null,
            description: claimInfo ? claimInfo.description : null,
            dataType: claimInfo ? claimInfo.dataType : null
        };
    }

    // Public methods.
    Authr.decodeToken = function (token) {
        if (!token) {
            return null;
        }
        token = token.trim();

        // Try to decode as JWT first.
        var decoded = tryDecodeJwt(token);
        if (decoded) {
            return decoded;
        }

        // Try to decode as a SAML Response.
        var decoded = tryDecodeSamlResponse(token);
        if (decoded) {
            return decoded;
        }

        return null;
    };

    Authr.parseToken = function (token) {
        var decodedToken = Authr.decodeToken(token);
        if (!decodedToken) {
            return null;
        }
        var claims = [];
        var isEncrypted = false;
        try {
            // Parse JWT JSON tokens.
            if (decodedToken.tokenType === 'JWT' && decodedToken.body) {
                Object.keys(decodedToken.body).forEach(function (claimType) {
                    var value = decodedToken.body[claimType];
                    claims.push(getClaimInfo(claimType, value));
                });
            }
            // Parse SAML XML tokens.
            if (decodedToken.tokenType === 'SAML' && decodedToken.body) {
                var parser = new DOMParser();
                var xml = parser.parseFromString(decodedToken.body, 'text/xml');
                if (xml.documentElement.nodeName !== "parsererror") {
                    var nsResolver = function (prefix) {
                        if (prefix === 'saml') return 'urn:oasis:names:tc:SAML:2.0:assertion';
                        return null;
                    }
                    // Find all <Attribute> XML nodes in the SAML namespace.
                    var attributeNodes = xml.evaluate('//saml:Attribute', xml, nsResolver, XPathResult.ANY_TYPE, null);
                    var attributeNode;
                    while (attributeNode = attributeNodes.iterateNext()) {
                        var claimType = attributeNode.getAttribute('Name');
                        // Find all child <AttributeValue> nodes that contain the claim value.
                        attributeNode.childNodes.forEach(function (attributeChildNode) {
                            if (attributeChildNode.nodeType === Node.ELEMENT_NODE && attributeChildNode.localName === 'AttributeValue') {
                                claims.push(getClaimInfo(claimType, attributeChildNode.textContent));
                            }
                        });
                    }

                    // Find an <EncryptedAssertion> XML node in the SAML namespace.
                    var encryptedAssertionNode = xml.evaluate('//saml:EncryptedAssertion', xml, nsResolver, XPathResult.ANY_TYPE, null);
                    if (encryptedAssertionNode.iterateNext()) {
                        isEncrypted = true;
                    }
                }
            }
        } catch (e) {
            console.log('Error parsing token: ' + e);
        }
        return {
            decodedToken: decodedToken,
            claims: claims,
            isEncrypted: isEncrypted
        };
    }

    Authr.formatDecodedToken = function (decodedToken) {
        if (decodedToken) {
            if (decodedToken.tokenType === 'JWT' && decodedToken.header && decodedToken.body) {
                return JSON.stringify(decodedToken.header, null, 2) + '.' + JSON.stringify(decodedToken.body, null, 2);
            }
            if (decodedToken.tokenType === 'SAML' && decodedToken.body) {
                return decodedToken.body;
            }
            return decodedToken;
        }
        return 'Invalid token';
    }

    Authr.showToast = function (message) {
        document.getElementById('toastMessageText').innerText = message;
        bootstrap.Toast.getOrCreateInstance(document.getElementById('toastMessage')).show();
    }
})(window.Authr = window.Authr || {});

new ClipboardJS('.btn-copy');

// Polyfills.
if (!String.prototype.startsWith) {
    String.prototype.startsWith = function (searchString, position) {
        position = position || 0;
        return this.substr(position, searchString.length) === searchString;
    };
}