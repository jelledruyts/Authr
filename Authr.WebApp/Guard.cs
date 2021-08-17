using System;

namespace Authr.WebApp
{
    public static class Guard
    {
        public static void NotEmpty(string value, string message)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException(message);
            }
        }
    }
}