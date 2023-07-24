using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;

namespace Authr.WebApp.Services
{
    public class FileSystemCertificateProvider : ICertificateProvider
    {
        private static IDictionary<string, X509Certificate2> certificates = new Dictionary<string, X509Certificate2>();
        private readonly IConfiguration configuration;
        private readonly IFileProvider fileProvider;
        private readonly string relativeBasePath;

        public FileSystemCertificateProvider(IConfiguration configuration, IFileProvider fileProvider, string relativeBasePath)
        {
            this.configuration = configuration;
            this.fileProvider = fileProvider;
            this.relativeBasePath = relativeBasePath;
        }

        public bool IsCertificateConfigured(string name)
        {
            return !string.IsNullOrWhiteSpace(this.configuration.GetValue<string>($"App:Certificates:{name}:Path"));
        }

        public Task<X509Certificate2> GetCertificateAsync(string name)
        {
            if (!certificates.ContainsKey(name))
            {
                var path = this.configuration.GetValue<string>($"App:Certificates:{name}:Path");
                var password = this.configuration.GetValue<string>($"App:Certificates:{name}:Password");
                if (!Path.IsPathRooted(path))
                {
                    var relativePath = Path.Combine(this.relativeBasePath, path);
                    path = this.fileProvider.GetFileInfo(relativePath).PhysicalPath;
                }
                certificates[name] = new X509Certificate2(path, password);
            }
            return Task.FromResult(certificates[name]);
        }
    }
}