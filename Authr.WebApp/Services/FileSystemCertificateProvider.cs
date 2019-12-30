using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.FileProviders;

namespace Authr.WebApp.Services
{
    public class FileSystemCertificateProvider : ICertificateProvider
    {
        private static IDictionary<string, X509Certificate2> certificates = new Dictionary<string, X509Certificate2>();
        private readonly IFileProvider fileProvider;

        public FileSystemCertificateProvider(IFileProvider fileProvider)
        {
            this.fileProvider = fileProvider;
        }

        public void LoadCertificate(string name, string path, string password)
        {
            if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(path) && !string.IsNullOrWhiteSpace(password))
            {
                if (!Path.IsPathRooted(path))
                {
                    path = this.fileProvider.GetFileInfo(path).PhysicalPath;
                }
                certificates[name] = new X509Certificate2(path, password);
            }
        }

        public Task<X509Certificate2> GetCertificateAsync(string name)
        {
            if (certificates.ContainsKey(name))
            {
                return Task.FromResult(certificates[name]);
            }
            return Task.FromResult<X509Certificate2>(null);
        }
    }
}