using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Authr.WebApp.Models;
using Azure;
using Azure.Storage.Blobs;

namespace Authr.WebApp.Services
{
    public class AzureStorageUserConfigurationProvider : IUserConfigurationProvider
    {
        private static readonly JsonSerializerOptions JsonSerializerOptions = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        private const string UserConfigurationFileName = "user-configuration.json";
        private readonly BlobServiceClient client;

        public AzureStorageUserConfigurationProvider(string connectionString)
        {
            this.client = new BlobServiceClient(connectionString);
        }

        public async Task<UserConfiguration> GetUserConfigurationAsync(string userId)
        {
            // Get the blob container for the user but don't create it if it doesn't yet exist.
            var containerClient = this.client.GetBlobContainerClient(GetBlobContainerName(userId));
            var blob = containerClient.GetBlobClient(UserConfigurationFileName);
            try
            {
                // Download the blob to a stream.
                var configuration = await blob.DownloadAsync();

                // Deerialize the JSON blob.
                return await JsonSerializer.DeserializeAsync<UserConfiguration>(configuration.Value.Content, JsonSerializerOptions);
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
            var containerClient = this.client.GetBlobContainerClient(GetBlobContainerName(userConfiguration.UserId));
            await containerClient.CreateIfNotExistsAsync();
            var blob = containerClient.GetBlobClient(UserConfigurationFileName);

            // Serialize the JSON stream to blob storage.
            using (var stream = new MemoryStream())
            using (var streamWriter = new StreamWriter(stream))
            {
                await JsonSerializer.SerializeAsync<UserConfiguration>(stream, userConfiguration, JsonSerializerOptions);
                await stream.FlushAsync();
                stream.Position = 0;
                await blob.UploadAsync(stream, overwrite: true);
            }
        }

        private static string GetBlobContainerName(string userId)
        {
            return $"user-{userId}";
        }
    }
}