namespace Authr.WebApp.Models
{
    public class ApiClientRequestOptions
    {
        public bool SaveIdentityService { get; set; }
        public string SaveIdentityServiceAsName { get; set; }
        public bool SaveClientApplication { get; set; }
        public string SaveClientApplicationAsName { get; set; }
        public bool SaveRequestTemplate { get; set; }
        public string SaveRequestTemplateAsName { get; set; }
        public string FlowId { get; set; }
    }
}