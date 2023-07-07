new Vue({
    el: '#app',
    data: function () {
        return {
            encodedToken: null,
            decryptedToken: null,
            errorMessage: null
        }
    },
    computed: {
        parsedToken: function () {
            return Authr.parseToken(this.encodedToken);
        },
    },
    filters: {
        token: function (decodedToken) {
            return Authr.formatDecodedToken(decodedToken);
        }
    },
    watch: {
        'encodedToken': function (newValue, oldValue) {
            // When the encoded token changes, the decrypted token is no longer valid.
            this.decryptedToken = null;
        }
    },
    methods: {
        decryptToken: function (token) {
            var that = this;
            axios.post('/api/decryptToken', { encryptedToken: token })
                .then(function (response) {
                    that.decryptedToken = response.data;
                })
                .catch(function (error) {
                    console.log(error);
                    that.errorMessage = error.message;
                    Authr.showToast(error.message);
                });
        }
    },
    created: function () {
        if (location.hash && location.hash.length > 1) {
            // Find the first valid token in the URL fragment and decode it.
            var that = this;
            window.location.hash.substring(1).split('&').map(function (item) {
                if (item.indexOf('=') >= 0) {
                    var value = decodeURIComponent(item.split('=')[1]);
                    var token = Authr.decodeToken(value);
                    if (token) {
                        that.encodedToken = value;
                    }
                }
            });
        }
    }
});