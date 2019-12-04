namespace Authr.WebApp.Models
{
    public class AuthViewModel
    {
        // TODO: Don't mix the Request that corresponds to the Response, and a NEW Request not yet submitted.
        // This means that the actual (NEW) Request should never be null but always have TimeCreated = null (rename to TimeSubmitted?)
        public AuthRequest Request { get; set; }
        public string RedirectUrl { get; set; }
        public AuthResponse Response { get; set; }
        public UserConfiguration UserConfiguration { get; set; }
    }
}