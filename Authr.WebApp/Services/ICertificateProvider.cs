using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Authr.WebApp.Services
{
    public interface ICertificateProvider
    {
        bool IsCertificateConfigured(string name);
        Task<X509Certificate2> GetCertificateAsync(string name);
    }
}