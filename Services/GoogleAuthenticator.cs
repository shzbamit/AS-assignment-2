namespace WebApplication1.Services
{
    using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages.Manage;
    using OtpSharp;
    using Google.Authenticator;


    public class GoogleAuthenticator
    {
        public string GenerateQrCodeUrl(string username, string secretKey)
        {
            // Generate the URL to display the QR code for Google Authenticator
            var baseUri = "https://chart.googleapis.com/chart?chs=200x200&cht=qr";
            var uri = $"{baseUri}&chl=otpauth://totp/{username}?secret={secretKey}&issuer=MyApp";
            return uri;
        }

        public bool ValidateTwoFactorPin(string secretKey, string code)
        {
            // Validate the 2FA code entered by the user
            var tfa = new TwoFactorAuthenticator();
            var result = tfa.ValidateTwoFactorPIN(secretKey, code);
            return result;
        }
    }

}
