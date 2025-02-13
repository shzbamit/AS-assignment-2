using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.ViewModels;
using WebApplication1.Services;
using WebApplication1.Model;

namespace WebApplication1.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<ApplicationUser> userManager;  // Use ApplicationUser
        private readonly SignInManager<ApplicationUser> signInManager; // Use ApplicationUser
        private readonly EncryptionService _encryptionService; // Inject the encryption service

        [BindProperty]
        public Register RModel { get; set; }

        public RegisterModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, EncryptionService encryptionService)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            _encryptionService = encryptionService; // Initialize the encryption service
        }

        public void OnGet()
        {
        }

        // Save data into the database and encrypt the credit card number
        public async Task<IActionResult> OnPostAsync()
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser()
                {
                    UserName = RModel.Email,
                    Email = RModel.Email,
                    FullName = RModel.FullName,
                    Gender = RModel.Gender,
                    MobileNo = RModel.MobileNo,
                    DeliveryAddress = RModel.DeliveryAddress,
                    AboutMe = RModel.AboutMe,
                    Photo = "", // Optional, can be added based on your logic
                    EncryptedCreditCardNumber = _encryptionService.Encrypt(RModel.CreditCardNumber) // Encrypt credit card number
                };

                var result = await userManager.CreateAsync(user, RModel.Password);
                if (result.Succeeded)
                {
                    await signInManager.SignInAsync(user, false);

                    // Store user info in session
                    HttpContext.Session.SetString("UserId", user.Id);
                    HttpContext.Session.SetString("UserName", user.UserName);
                    HttpContext.Session.SetString("Email", user.Email);

                    // Store encrypted credit card in session
                    HttpContext.Session.SetString("EncryptedCreditCard", user.EncryptedCreditCardNumber);

                    // Set session ID for detecting multiple logins
                    HttpContext.Session.SetString("SessionId", HttpContext.Session.Id);

                    return RedirectToPage("Index");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }

            return Page();
        }
    }
}
