namespace WebApplication1.Pages
{
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using Microsoft.AspNetCore.Identity;
    using WebApplication1.Model;
    using System.Threading.Tasks;

    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public ResetPasswordModel(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        [BindProperty]
        public string Token { get; set; }

        [BindProperty]
        public string Email { get; set; }

        [BindProperty]
        public string NewPassword { get; set; }

        [BindProperty]
        public string ConfirmPassword { get; set; }

        public IActionResult OnGet(string token, string email)
        {
            if (token == null || email == null)
            {
                return RedirectToPage("Login");
            }

            Token = token;
            Email = email;
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (NewPassword != ConfirmPassword)
            {
                ModelState.AddModelError(string.Empty, "Passwords do not match.");
                return Page();
            }

            var user = await _userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                return RedirectToPage("Login");
            }

            var result = await _userManager.ResetPasswordAsync(user, Token, NewPassword);
            if (result.Succeeded)
            {
                return RedirectToPage("Login");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return Page();
        }
    }

}
