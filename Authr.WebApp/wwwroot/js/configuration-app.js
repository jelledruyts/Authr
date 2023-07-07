new Vue({
    el: '#app',
    data: function () {
        return {
            userConfiguration: null,
            identityServiceImportRequestParameters: { importType: 'Metadata' },
            processing: false,
            errorMessage: null
        }
    },
    methods: {
        deleteItem: function (array, value) {
            array.splice(array.indexOf(value), 1);
        },
        moveItemUp: function (array, value) {
            var index = array.indexOf(value);
            array.splice(index, 1);
            array.splice(index - 1, 0, value);
        },
        moveItemDown: function (array, value) {
            var index = array.indexOf(value);
            array.splice(index, 1);
            array.splice(index + 1, 0, value);
        },
        addIdentityService: function (array) {
            array.push({ clientApplications: [] });
        },
        addClientApplication: function (array) {
            array.push({});
        },
        saveUserConfiguration: function () {
            this.processing = true;
            this.errorMessage = null;
            var that = this;
            axios.post('/api/userConfiguration', this.userConfiguration)
                .then(function (response) {
                    that.userConfiguration = response.data;
                    that.processing = false;
                    Authr.showToast('Configuration saved successfully');
                })
                .catch(function (error) {
                    console.log(error);
                    that.errorMessage = error.message;
                    Authr.showToast(error.message);
                    that.processing = false;
                });
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
                        that.userConfiguration.identityServices.push(identityService);
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
        this.userConfiguration = globalUserConfiguration;
    }
});