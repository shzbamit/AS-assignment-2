using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Services;

namespace WebApplication1.Pages
{
    [Authorize]
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly EncryptionService _encryptionService;

        public IndexModel(ILogger<IndexModel> logger, EncryptionService encryptionService)
        {
            _logger = logger;
            _encryptionService = encryptionService;
        }

        public string UserName { get; set; }
        public string Email { get; set; }
        public string DecryptedCreditCard { get; set; }

        public string EncryptedCreditCard { get; set; }

        public void OnGet()
        {
            // Check if session exists
            var userId = HttpContext.Session.GetString("UserId");
            var sessionId = HttpContext.Session.GetString("SessionId");

            if (userId == null)
            {
                // If the session is expired or invalid, redirect to the login page
                RedirectToPage("/Login");
                return;
            }

            // Detect if the session ID has changed (indicating a different tab or device login)
            var newSessionId = HttpContext.Session.Id;
            if (sessionId != newSessionId)
            {
                // This could indicate a different browser tab or device login
                // Perform additional actions like logging the user out or showing a warning message
                // For this example, we'll redirect to login
                HttpContext.Session.Clear();
                RedirectToPage("/Login");
                return;
            }

            // Store the current session ID to detect future logins
            HttpContext.Session.SetString("SessionId", newSessionId);

            // Retrieve the user info from session
            UserName = HttpContext.Session.GetString("UserName");
            Email = HttpContext.Session.GetString("Email");

            // Retrieve encrypted credit card
            EncryptedCreditCard = HttpContext.Session.GetString("EncryptedCreditCard");

            if (!string.IsNullOrEmpty(EncryptedCreditCard))
            {
                DecryptedCreditCard = _encryptionService.Decrypt(EncryptedCreditCard);
            }
        }

        public IActionResult OnPostLogout()
        {
            HttpContext.Session.Clear(); // Clear all session data
            HttpContext.SignOutAsync(); // Sign out from authentication
            return RedirectToPage("/Login"); // Redirect to login page
        }
    }

}
