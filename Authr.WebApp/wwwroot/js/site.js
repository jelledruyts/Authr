(function (Authr, undefined) {
    // Private methods and properties.
    var wellKnownClaims = {};
    addClaimInfo(wellKnownClaims, 'acct', 'Account Status', 'The account status of the user in the tenant that issued the token. If the user is a member of the tenant, the value is "0". If they are a guest, the value is "1".', null);
    addClaimInfo(wellKnownClaims, 'acr', 'Authentication Context Class Reference', 'The Authentication Context Class values that the authentication performed satisfied, implying a Level Of Assurance.', null);
    addClaimInfo(wellKnownClaims, 'address', 'Address', 'The preferred postal address of the \'user\'.', null);
    addClaimInfo(wellKnownClaims, 'aio', 'Internal', 'An internal claim used by Azure Active Directory. Should be ignored.', null);
    addClaimInfo(wellKnownClaims, 'altsecid', 'Alternate Security ID', 'An alternate ID that allows users to have multiple social accounts tied to their local user account.', null);
    addClaimInfo(wellKnownClaims, 'amr', 'Authentication Methods References', 'The authentication methods used by the user during authentication, e.g. a password or OTP.', null);
    addClaimInfo(wellKnownClaims, 'app_displayname', 'App Display Name', 'The display name of the client application.', null);
    addClaimInfo(wellKnownClaims, 'appid', 'Application ID', 'The application ID of the client that is using the token to access a resource (either on behalf of itself or a user).', null);
    addClaimInfo(wellKnownClaims, 'appidacr', 'Application Authentication Context Class Reference', 'The authentication mechanism used by the application. For a public client, this is "0". If client ID and client secret were used, this is "1". If a client certificate was used, this is "2".', null);
    addClaimInfo(wellKnownClaims, 'at_hash', 'Access Token Hash', 'A hash of the OAuth 2.0 Access Token.', null);
    addClaimInfo(wellKnownClaims, 'aud', 'Audience', 'The audience of the targeted application, i.e. the intended recipient of the token.', null);
    addClaimInfo(wellKnownClaims, 'auth_time', 'Authentication Time', 'The time the user has performed the actual authentication.', 'UnixTime');
    addClaimInfo(wellKnownClaims, 'azp', 'Authorized Party', 'The party to which the ID Token was issued.', null);
    addClaimInfo(wellKnownClaims, 'azpacr', 'Application Authentication Context Class Reference', 'The authentication mechanism used by the application. For a public client, this is "0". If client ID and client secret were used, this is "1". If a client certificate was used, this is "2".', null);
    addClaimInfo(wellKnownClaims, 'birthdate', 'Birthday', 'The birthday of the user.', null);
    addClaimInfo(wellKnownClaims, 'c_hash', 'Authorization Code Hash', 'A hash of the OAuth 2.0 Authorization Code that was used to redeem this token.', null);
    addClaimInfo(wellKnownClaims, 'city', 'City', 'The city in which the user is located.', null);
    addClaimInfo(wellKnownClaims, 'country', 'Country', 'The country in which the user is located.', null);
    addClaimInfo(wellKnownClaims, 'email', 'Email', 'The email address of the user.', null);
    addClaimInfo(wellKnownClaims, 'email_verified', 'Email Verified', 'Indicates if the user\'s email address has been verified.', null);
    addClaimInfo(wellKnownClaims, 'emails', 'Emails', 'The email addresses of the user.', null);
    addClaimInfo(wellKnownClaims, 'exp', 'Expiration', 'The time after which the token cannot be used anymore.', 'UnixTime');
    addClaimInfo(wellKnownClaims, 'family_name', 'Family Name', 'The surname or last name of the user.', null);
    addClaimInfo(wellKnownClaims, 'gender', 'Gender', 'The gender of the user.', null);
    addClaimInfo(wellKnownClaims, 'given_name', 'Given Name', 'The given name or first name of the user.', null);
    addClaimInfo(wellKnownClaims, 'groups', 'Groups', 'The group memberships of the user.', null);
    addClaimInfo(wellKnownClaims, 'hasgroups', 'Has Groups', 'Indicates if the user has at least one group membership.', null);
    addClaimInfo(wellKnownClaims, 'hd', 'Hosted Domain', 'The hosted G Suite domain of the user.', null);
    addClaimInfo(wellKnownClaims, 'http://schemas.microsoft.com/claims/authnclassreference', 'Authentication Context Class Reference', 'The Authentication Context Class values that the authentication performed satisfied, implying a Level Of Assurance.', null);
    addClaimInfo(wellKnownClaims, 'http://schemas.microsoft.com/claims/authnmethodsreferences', 'Authentication Methods References', 'The authentication methods used by the user during authentication, e.g. a password or OTP.', null);
    addClaimInfo(wellKnownClaims, 'http://schemas.microsoft.com/identity/claims/scope', 'Scopes', 'The scopes, i.e. the permissions granted to the client application to act on behalf of the user.', null);
    addClaimInfo(wellKnownClaims, 'http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant', 'Authentication Time', 'The time the user has performed the actual authentication.', 'UnixTime');
    addClaimInfo(wellKnownClaims, 'iat', 'Issued At', 'The time the token was issued.', 'UnixTime');
    addClaimInfo(wellKnownClaims, 'idp', 'Identity Provider', 'The Identity Provider that authenticated the subject of the token, if that is different from the issuer of the token.', null);
    addClaimInfo(wellKnownClaims, 'in_corp', 'In Corp', 'Indicates if the user is authenticating from a corporate network.', null);
    addClaimInfo(wellKnownClaims, 'ipaddr', 'IP Address', 'The IP address the user authenticated from.', null);
    addClaimInfo(wellKnownClaims, 'iss', 'Issuer', 'The issuer, i.e. the Security Token Service that issued the token.', null);
    addClaimInfo(wellKnownClaims, 'jobTitle', 'Job Title', 'The job title of the user.', null);
    addClaimInfo(wellKnownClaims, 'jti', 'JWT ID', 'A unique identifier for the token.', null);
    addClaimInfo(wellKnownClaims, 'locale', 'Locale', 'The locale of the user.', null);
    addClaimInfo(wellKnownClaims, 'middle_name', 'Middle Name', 'The middle name of the user.', null);
    addClaimInfo(wellKnownClaims, 'name', 'Subject Name', 'A human-readable value that identifies the user in its fullest form.', null);
    addClaimInfo(wellKnownClaims, 'nbf', 'Not Before', 'The time before which the token cannot be used.', 'UnixTime');
    addClaimInfo(wellKnownClaims, 'newUser', 'New User', 'Indicates if the user was registered as a new user during the authentication request that generated the token.', null);
    addClaimInfo(wellKnownClaims, 'nickname', 'Nickname', 'The nickname of the user.', null);
    addClaimInfo(wellKnownClaims, 'nonce', 'Nonce', 'The nonce value used to validate the token response.', null);
    addClaimInfo(wellKnownClaims, 'oid', 'Object ID', 'The unique and immutable object identifier of the user, which is always the same identifier even across different applications.', null);
    addClaimInfo(wellKnownClaims, 'onprem_sid', 'On-Prem SID', 'The Security Identifier (SID) of the user in an on-premises authentication system.', null);
    addClaimInfo(wellKnownClaims, 'phone_number', 'Phone Number', 'The preferred telephone number of the user.', null);
    addClaimInfo(wellKnownClaims, 'phone_number_verified', 'Phone Number Verified', 'Indicates if the user\'s phone number has been verified.', null);
    addClaimInfo(wellKnownClaims, 'picture', 'Picture', 'The URL of the profile picture of the user.', null);
    addClaimInfo(wellKnownClaims, 'platf', 'Device Platform', 'Restricted to managed devices that can verify the device type.', null);
    addClaimInfo(wellKnownClaims, 'postalCode', 'Postal Code', 'The postal code of the user\'s address.', null);
    addClaimInfo(wellKnownClaims, 'preferred_name', 'Preferred Name', 'The primary username that the user should be represented as.', null);
    addClaimInfo(wellKnownClaims, 'preferred_username', 'Preferred Username', 'The primary username that the user should be represented as.', null);
    addClaimInfo(wellKnownClaims, 'profile', 'Profile', 'The URL of the profile page of the user.', null);
    addClaimInfo(wellKnownClaims, 'puid', 'Passport Unique ID', 'The unique identifier of the user in the Microsoft Passport system.', null);
    addClaimInfo(wellKnownClaims, 'pwd_exp', 'Password Expiration', 'The time the subject\'s password expires.', 'UnixTime');
    addClaimInfo(wellKnownClaims, 'pwd_url', 'Password URL', 'The URL where the user can reset their password.', null);
    addClaimInfo(wellKnownClaims, 'rh', 'Internal', 'An internal claim used by Azure Active Directory. Should be ignored.', null);
    addClaimInfo(wellKnownClaims, 'roles', 'Roles', 'The roles that are assigned to the user for the application.', null);
    addClaimInfo(wellKnownClaims, 'scp', 'Scopes', 'The scopes, i.e. the permissions granted to the client application to act on behalf of the user.', null);
    addClaimInfo(wellKnownClaims, 'signin_state', 'Sign-In State', 'The sign-in state of the user.', null);
    addClaimInfo(wellKnownClaims, 'state', 'State', 'The state or province in which the user is located.', null);
    addClaimInfo(wellKnownClaims, 'streetAddress', 'Street Address', 'The street address where the user is located.', null);
    addClaimInfo(wellKnownClaims, 'sub', 'Subject', 'The subject, i.e. the principal about which the token asserts information, such as the user of an application; this can have a different value for the same user depending on the application.', null);
    addClaimInfo(wellKnownClaims, 'tfp', 'Trust Framework Policy', 'The Trust Framework Policy, i.e. the user flow (policy) through which the user authenticated in Azure AD B2C.', null);
    addClaimInfo(wellKnownClaims, 'tid', 'Tenant ID', 'The identifier of the tenant in the Security Token Service that is the home realm of the user.', null);
    addClaimInfo(wellKnownClaims, 'unique_name', 'Unique Name', 'A human-readable value that identifies the subject of the token.', null);
    addClaimInfo(wellKnownClaims, 'updated_at', 'Updated At', 'The time the user\'s information was last updated.', 'UnixTime');
    addClaimInfo(wellKnownClaims, 'upn', 'UPN', 'The User Principal Name (UPN) of the user.', null);
    addClaimInfo(wellKnownClaims, 'uti', 'Internal', 'An internal claim used by Azure Active Directory. Should be ignored.', null);
    addClaimInfo(wellKnownClaims, 'ver', 'Version', 'The version of the token format.', null);
    addClaimInfo(wellKnownClaims, 'website', 'Website', 'The URL of the user\'s web page.', null);
    addClaimInfo(wellKnownClaims, 'wids', 'Tenant-Wide Roles', 'Denotes the tenant-wide roles assigned to the user, as an array of RoleTemplateID GUIDs.', null);
    addClaimInfo(wellKnownClaims, 'xms_st', 'Internal', 'An internal claim used by Azure Active Directory. Should be ignored.', null);
    addClaimInfo(wellKnownClaims, 'xms_tcdt', 'Internal', 'An internal claim used by Azure Active Directory. Should be ignored.', 'UnixTime');
    addClaimInfo(wellKnownClaims, 'zoneinfo', 'Zone Info', 'The time zone where the user is located.', null);
        
    function addClaimInfo(bag, claimType, displayName, description, dataType) {
        bag[claimType] = {
            claimType: claimType,
            displayName: displayName,
            description: description,
            dataType: dataType || 'string'
        };
    }

    function decodeJwt(jwt) {
        if (jwt) {
            var jwtParts = jwt.split('.');
            if (jwtParts.length > 1) {
                var signature = null;
                if (jwtParts.length > 2) {
                    signature = jwtParts[2];
                }
                return {
                    tokenType: 'JWT',
                    header: decodeJwtPart(jwtParts[0]),
                    body: decodeJwtPart(jwtParts[1]),
                    signature: signature
                };
            }
        }
        return null;
    };

    function decodeJwtPart(jwtPart) {
        try {
            var jwtPartBase64 = jwtPart.replace(/-/g, '+').replace(/_/g, '/');
            var jwtPartJson = decodeURIComponent(atob(jwtPartBase64).split('').map(function(c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));
            return JSON.parse(jwtPartJson);
        } catch (e) {
            return null;
        }
    };

    // Public methods.
    Authr.decodeToken = function (token) {
        return decodeJwt(token);
    };

    Authr.parseToken = function (token) {
        var decodedToken = Authr.decodeToken(token);
        if (decodedToken && decodedToken.tokenType === 'JWT' && decodedToken.body) {
            var claims = [];
            try {
                Object.keys(decodedToken.body).forEach(claimType => {
                    var value = decodedToken.body[claimType];
                    var interpretedValue = null;
                    var claimInfo = wellKnownClaims[claimType];
                    if (claimInfo && claimInfo.dataType) {
                        if (claimInfo.dataType === 'UnixTime' && typeof value === 'number') {
                            var dateValue = new Date(0); // The zero value sets the date instance to the Unix time epoch.
                            dateValue.setUTCSeconds(value);
                            interpretedValue = dateValue.toLocaleString() + ' (local time)';
                        }
                    }
                    claims.push({
                        claimType: claimType,
                        value: value,
                        interpretedValue: interpretedValue,
                        displayName: claimInfo ? claimInfo.displayName : null,
                        description: claimInfo ? claimInfo.description : null,
                        dataType: claimInfo ? claimInfo.dataType : null
                    });
                });
            } catch (e) {
                console.log(e);
            }
            return {
                decodedToken: decodedToken,
                claims: claims
            };
        }
    }
})(window.Authr = window.Authr || {});