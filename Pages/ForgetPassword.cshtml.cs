using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using WebApplication1.Model;
using WebApplication1.Services;  // Use the correct namespace for your custom IEmailSender
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;

namespace WebApplication1.Pages
{
    public class ForgetPasswordModel : PageModel
    {
        private readonly Services.IEmailSender _emailSender; // Fully qualify the namespace
        private readonly UserManager<ApplicationUser> _userManager;

        public ForgetPasswordModel(Services.IEmailSender emailSender, UserManager<ApplicationUser> userManager)
        {
            _emailSender = emailSender;
            _userManager = userManager;
        }

        [BindProperty]
        public string Email { get; set; }

        public async Task<IActionResult> OnPostAsync()
        {
            if (string.IsNullOrEmpty(Email))
            {
                return Page();
            }

            var user = await _userManager.FindByEmailAsync(Email);

            if (user == null)
            {
                // User not found, handle the case (you can redirect to a page with an error message)
                return RedirectToPage("Login");
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetUrl = Url.Page("ResetPassword", new { token, email = user.Email });

            var message = $"Click the link to reset your password: https://localhost:7257{resetUrl}";

            // Send the reset email to the user's email
            await _emailSender.SendEmailAsync(Email, "Reset Your Password", message);

            return RedirectToPage("ResetPassword");
        }
    }
}
