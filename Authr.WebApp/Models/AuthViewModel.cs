namespace Authr.WebApp.Models
{
    public class AuthViewModel
    {
        public AuthRequestParameters RequestParameters { get; set; }
        public string RedirectUrl { get; set; }
        public AuthResponse Response { get; set; }
        public UserConfiguration UserConfiguration { get; set; }
    }
}