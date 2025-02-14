using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;
using System.Threading.Tasks;

namespace WebApplication1.Pages
{
    public class TwoFactorAuthModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;

        public TwoFactorAuthModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
        }

        // Bind the OTP input field to this property
        [BindProperty]
        public string Otp { get; set; }

        public string ErrorMessage { get; set; }

        public async Task<IActionResult> OnPostAsync()
        {
            if (string.IsNullOrEmpty(Otp))
            {
                ErrorMessage = "The authentication code cannot be empty.";
                return Page();
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                ErrorMessage = "User not found.";
                return Page();
            }

            // Verify the two-factor authentication code using Google Authenticator
            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(Otp, false, false);

            if (result.Succeeded)
            {
                // Store user info in session on successful 2FA
                HttpContext.Session.SetString("UserId", user.Id);
                HttpContext.Session.SetString("UserName", user.UserName);
                HttpContext.Session.SetString("Email", user.Email);

                // Store encrypted credit card in session
                HttpContext.Session.SetString("EncryptedCreditCard", user.EncryptedCreditCardNumber);

                // Set session ID for detecting multiple logins
                HttpContext.Session.SetString("SessionId", HttpContext.Session.Id);

                // Redirect to the Index page
                return RedirectToPage("/Index");
            }
            else
            {
                ErrorMessage = "Invalid authentication code.";
                return Page();
            }
        }
    }

}
