using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using System.Web;
using Authr.WebApp.Models;
using Azure;
using Azure.Storage.Blobs;

namespace Authr.WebApp.Services
{
    public class AzureStorageAuthFlowCacheProvider : IAuthFlowCacheProvider
    {
        private static readonly JsonSerializerOptions JsonSerializerOptions = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        private const string BlobContainerName = "authflowcache";
        private readonly BlobServiceClient client;

        public AzureStorageAuthFlowCacheProvider(string connectionString)
        {
            this.client = new BlobServiceClient(connectionString);
        }

        public async Task<AuthFlow> GetAuthFlowAsync(string reference)
        {
            // Get the blob container for the flow but don't create it if it doesn't yet exist.
            var containerClient = this.client.GetBlobContainerClient(BlobContainerName);
            var blob = containerClient.GetBlobClient(GetBlobName(reference));
            try
            {
                // Download the blob to a stream.
                var flow = await blob.DownloadAsync();

                // Deerialize the JSON blob.
                return await JsonSerializer.DeserializeAsync<AuthFlow>(flow.Value.Content, JsonSerializerOptions);
            }
            catch (RequestFailedException exc)
            {
                if (string.Equals(exc.ErrorCode, "BlobNotFound", StringComparison.OrdinalIgnoreCase) || string.Equals(exc.ErrorCode, "ContainerNotFound", StringComparison.OrdinalIgnoreCase))
                {
                    // Ignore containers and blobs that don't exist.
                    return null;
                }
                else
                {
                    throw;
                }
            }
        }

        public async Task SetAuthFlowAsync(string reference, AuthFlow flow)
        {
            // Get the blob container for the flow and create it if it doesn't yet exist.
            var containerClient = this.client.GetBlobContainerClient(BlobContainerName);
            await containerClient.CreateIfNotExistsAsync();
            var blob = containerClient.GetBlobClient(GetBlobName(reference));

            // Serialize the JSON stream to blob storage.
            using (var stream = new MemoryStream())
            using (var streamWriter = new StreamWriter(stream))
            {
                await JsonSerializer.SerializeAsync<AuthFlow>(stream, flow, JsonSerializerOptions);
                await stream.FlushAsync();
                stream.Position = 0;
                await blob.UploadAsync(stream, overwrite: true);
            }
        }

        public async Task RemoveAuthFlowAsync(string reference)
        {
            // Get the blob container for the flow but don't create it if it doesn't yet exist.
            var containerClient = this.client.GetBlobContainerClient(BlobContainerName);
            var blob = containerClient.GetBlobClient(GetBlobName(reference));
            await blob.DeleteIfExistsAsync();
        }

        private static string GetBlobName(string reference)
        {
            return $"flow-{HttpUtility.UrlEncode(reference)}.json";
        }
    }
}