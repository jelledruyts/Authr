namespace Authr.WebApp.Models
{
    public class AuthViewModel
    {
        public AuthRequestParameters RequestParameters { get; set; }
        public string RequestedRedirectUrl { get; set; }
        public string RequestedPageContent { get; set; }
        public AuthResponse Response { get; set; }
        public AuthFlow Flow { get; set; }
        public UserConfiguration UserConfiguration { get; set; }
        public string GeneratedLink { get; set; }
    }
}