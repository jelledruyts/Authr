using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Azure.Storage.Blobs;
using Microsoft.Extensions.Configuration;

namespace Authr.WebApp.Services
{
    public class AzureStorageCertificateProvider : ICertificateProvider
    {
        private static IDictionary<string, X509Certificate2> certificates = new Dictionary<string, X509Certificate2>();
        private readonly IConfiguration configuration;
        private readonly BlobServiceClient client;

        public AzureStorageCertificateProvider(IConfiguration configuration, string connectionString)
        {
            this.configuration = configuration;
            this.client = new BlobServiceClient(connectionString);
        }

        public async Task<X509Certificate2> GetCertificateAsync(string name)
        {
            if (!certificates.ContainsKey(name))
            {
                var path = this.configuration.GetValue<string>($"App:Certificates:{name}:Path");
                var password = this.configuration.GetValue<string>($"App:Certificates:{name}:Password");
                var containerClient = this.client.GetBlobContainerClient("certificates");
                var blob = containerClient.GetBlobClient(path);
                var certificateBlob = await blob.DownloadAsync();
                using (var streamReader = new BinaryReader(certificateBlob.Value.Content))
                {
                    var certificateBytes = streamReader.ReadBytes((int)certificateBlob.Value.Details.ContentLength);
                    certificates[name] = new X509Certificate2(certificateBytes, password);
                }
            }
            return certificates[name];
        }
    }
}