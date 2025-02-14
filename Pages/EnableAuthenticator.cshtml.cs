using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;
using WebApplication1.Services;

namespace WebApplication1.Pages
{
    public class EnableAuthenticatorModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<EnableAuthenticatorModel> _logger; // Declare the _logger field

        // Inject the logger into the constructor
        public EnableAuthenticatorModel(UserManager<ApplicationUser> userManager, ILogger<EnableAuthenticatorModel> logger)
        {
            _userManager = userManager;
            _logger = logger; // Assign the injected logger to the _logger field
        }

        public string QRCodeUri { get; set; }
        public string SecretKey { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            // Generate TOTP Secret Key
            var key = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(key))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                key = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            SecretKey = key;
            QRCodeUri = $"otpauth://totp/MyApp:{user.Email}?secret={key}&issuer=MyApp";

            // Log the QRCodeUri value
            _logger.LogInformation($"QRCodeUri: {QRCodeUri}");

            return Page();
        }

        public IActionResult OnPostContinue()
        {
            return RedirectToPage("VerifyAuthenticator");
        }
    }
}
