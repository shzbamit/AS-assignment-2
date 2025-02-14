using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.ViewModels;
using WebApplication1.Services;
using System.Threading.Tasks;
using WebApplication1.Model;

namespace WebApplication1.Pages
{
    public class LoginModel : PageModel
    {
        [BindProperty]
        public Login LModel { get; set; }
        public string LockoutMessage { get; set; }

        [BindProperty]
        public string ReCaptchaToken { get; set; } // Captures reCAPTCHA token

        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly ReCaptchaService _reCaptchaService;
        private readonly UserManager<ApplicationUser> _userManager;

        public LoginModel(SignInManager<ApplicationUser> signInManager, ReCaptchaService reCaptchaService, UserManager<ApplicationUser> userManager)
        {
            this.signInManager = signInManager;
            _reCaptchaService = reCaptchaService;
            _userManager = userManager;
        }

        public void OnGet()
        {
            // Clear session data when accessing the login page
            HttpContext.Session.Clear();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            // Validate reCAPTCHA token
            var isCaptchaValid = await _reCaptchaService.VerifyReCaptchaAsync(ReCaptchaToken);
            if (!isCaptchaValid)
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA validation failed. Please try again.");
                return Page();
            }

            if (ModelState.IsValid)
            {
                Console.WriteLine($"Attempting login with email: {LModel.Email}");

                // Find user by email
                var user = await _userManager.FindByEmailAsync(LModel.Email);
                if (user == null)
                {
                    ModelState.AddModelError("", "Invalid email or password.");
                    return Page();
                }

                // Password sign-in
                var result = await signInManager.PasswordSignInAsync(LModel.Email, LModel.Password, true, true);

                if (result.Succeeded)
                {
                    // Store user info in session on successful login
                    HttpContext.Session.SetString("UserId", user.Id);
                    HttpContext.Session.SetString("UserName", user.UserName);
                    HttpContext.Session.SetString("Email", user.Email);

                    // Store encrypted credit card in session
                    HttpContext.Session.SetString("EncryptedCreditCard", user.EncryptedCreditCardNumber);

                    // Set session ID for detecting multiple logins
                    HttpContext.Session.SetString("SessionId", HttpContext.Session.Id);

                    // Check for two-factor authentication (if enabled)
                    if (await _userManager.GetTwoFactorEnabledAsync(user))
                    {
                        var providers = await _userManager.GetValidTwoFactorProvidersAsync(user);
                        if (providers.Contains("Authenticator"))
                        {
                            // Redirect to the two-factor authentication page
                            return RedirectToPage("TwoFactorAuth");
                        }
                    }

                    return RedirectToPage("Index"); // Redirect to home page after successful login
                }

                // Handle failure reasons
                if (result.IsLockedOut)
                {
                    ModelState.AddModelError("", "Your account is locked due to multiple failed login attempts.");
                    LockoutMessage = "Your account is locked. Try again later.";
                }
                else if (result.RequiresTwoFactor)
                {
                    // Redirect to the 2FA page if needed
                    return RedirectToPage("TwoFactorAuth");
                }
                else
                {
                    ModelState.AddModelError("", "Invalid email or password.");
                }

                // Increment failed attempts and lockout if needed
                await _userManager.AccessFailedAsync(user);
                if (await _userManager.GetAccessFailedCountAsync(user) >= 3)
                {
                    await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddMinutes(1));
                    LockoutMessage = "Your account has been locked due to multiple failed login attempts. Try again in 5 minutes.";
                }
            }

            return Page();
        }

    }
}
