using System;
using System.IO;
using System.Threading.Tasks;
using Authr.WebApp.Models;
using Azure;
using Azure.Storage.Blobs;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace Authr.WebApp.Services
{
    public class AzureStorageUserConfigurationProvider : IUserConfigurationProvider
    {
        private const string UserConfigurationFileName = "user-configuration.json";
        private readonly BlobServiceClient client;

        public AzureStorageUserConfigurationProvider(string connectionString)
        {
            this.client = new BlobServiceClient(connectionString);
        }

        public async Task<UserConfiguration> GetUserConfigurationAsync(string userId)
        {
            // Get the blob container for the user but don't create it if it doesn't yet exist.
            var containerClient = this.client.GetBlobContainerClient(userId);
            var blob = containerClient.GetBlobClient(UserConfigurationFileName);
            try
            {
                // Download the blob to a stream.
                var configuration = await blob.DownloadAsync();

                // Deerialize the JSON blob.
                var serializer = GetJsonSerializer();
                using (var streamReader = new StreamReader(configuration.Value.Content))
                using (var jsonReader = new JsonTextReader(streamReader))
                {
                    return serializer.Deserialize<UserConfiguration>(jsonReader);
                }
            }
            catch (RequestFailedException exc)
            {
                if (string.Equals(exc.ErrorCode, "BlobNotFound", StringComparison.OrdinalIgnoreCase) || string.Equals(exc.ErrorCode, "ContainerNotFound", StringComparison.OrdinalIgnoreCase))
                {
                    // Ignore containers and blobs that don't exist.
                }
                else
                {
                    throw;
                }
            }
            // If there is no container or blob, then return a new user configuration object.
            return new UserConfiguration
            {
                UserId = userId
            };
        }

        public async Task SaveUserConfigurationAsync(UserConfiguration userConfiguration)
        {
            // Get the blob container for the user and create it if it doesn't yet exist.
            var containerClient = this.client.GetBlobContainerClient(userConfiguration.UserId);
            await containerClient.CreateIfNotExistsAsync();
            var blob = containerClient.GetBlobClient(UserConfigurationFileName);

            // Serialize the JSON stream to blob storage.
            var serializer = GetJsonSerializer();
            using (var stream = new MemoryStream())
            using (var streamWriter = new StreamWriter(stream))
            using (var jsonWriter = new JsonTextWriter(streamWriter))
            {
                serializer.Serialize(jsonWriter, userConfiguration);
                await jsonWriter.FlushAsync();
                stream.Position = 0;
                await blob.UploadAsync(stream, overwrite: true);
            }
        }

        private static JsonSerializer GetJsonSerializer()
        {
            return new JsonSerializer
            {
                ContractResolver = new CamelCasePropertyNamesContractResolver()
            };
        }
    }
}