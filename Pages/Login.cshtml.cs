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
            // Validate reCAPTCHA
            var isCaptchaValid = await _reCaptchaService.VerifyReCaptchaAsync(ReCaptchaToken);
            if (!isCaptchaValid)
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA validation failed. Please try again.");
                return Page();
            }

            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(LModel.Email);
                if (user == null)
                {
                    ModelState.AddModelError("", "Invalid email or password.");
                    return Page();
                }

                // Check if the account is locked
                if (await _userManager.IsLockedOutAsync(user))
                {
                    var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
                    var remainingTime = lockoutEnd.HasValue ? (lockoutEnd.Value.UtcDateTime - DateTime.UtcNow).TotalMinutes : 0;

                    LockoutMessage = $"Your account is locked. Try again in {remainingTime:F0} minutes.";
                    return Page();
                }

                // Attempt login
                var identityResult = await signInManager.PasswordSignInAsync(LModel.Email, LModel.Password, LModel.RememberMe, true);

                if (identityResult.Succeeded)
                {
                    // Successful login, reset failed attempts
                    await _userManager.ResetAccessFailedCountAsync(user);

                    HttpContext.Session.SetString("UserId", user.Id);
                    HttpContext.Session.SetString("UserName", user.UserName);
                    HttpContext.Session.SetString("Email", user.Email);
                    HttpContext.Session.SetString("EncryptedCreditCard", user.EncryptedCreditCardNumber);
                    HttpContext.Session.SetString("SessionId", HttpContext.Session.Id);

                    return RedirectToPage("Index");
                }
                else
                {
                    // Increase failed login count
                    await _userManager.AccessFailedAsync(user);

                    // Lock the account if max attempts reached
                    if (await _userManager.GetAccessFailedCountAsync(user) >= 3)
                    {
                        await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddMinutes(1));
                        LockoutMessage = "Your account has been locked due to multiple failed login attempts. Try again in 5 minutes.";
                    }

                    ModelState.AddModelError("", "Invalid email or password.");
                }
            }

            return Page();
        }
    }
}
