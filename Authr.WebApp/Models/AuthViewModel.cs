namespace Authr.WebApp.Models
{
    public class AuthViewModel
    {
        public AuthRequest Request { get; set; }
        public AuthResponse Response { get; set; }
        public UserConfiguration UserConfiguration { get; set; }
    }
}