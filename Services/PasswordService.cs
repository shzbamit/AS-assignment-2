namespace WebApplication1.Services
{
    using System;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Identity;
    using WebApplication1.Model;

    public class PasswordService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public PasswordService(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        public async Task<IdentityResult> ChangePasswordAsync(ApplicationUser user, string currentPassword, string newPassword)
        {
            // Check current password
            var checkCurrentPassword = await _userManager.CheckPasswordAsync(user, currentPassword);
            if (!checkCurrentPassword)
            {
                return IdentityResult.Failed(new IdentityError { Description = "Current password is incorrect." });
            }

            // Ensure new password is not the same as the current password
            if (currentPassword == newPassword)
            {
                return IdentityResult.Failed(new IdentityError { Description = "New password cannot be the same as the current password." });
            }

            // Check password history (last 2 passwords)
            foreach (var history in user.PreviousPasswords.OrderByDescending(p => p.DateChanged).Take(2))
            {
                if (_userManager.PasswordHasher.VerifyHashedPassword(user, history.HashedPassword, newPassword) == PasswordVerificationResult.Success)
                {
                    return IdentityResult.Failed(new IdentityError { Description = "New password must not match your last 2 passwords." });
                }
            }

            // Change password
            var result = await _userManager.ChangePasswordAsync(user, currentPassword, newPassword);
            if (result.Succeeded)
            {
                // Store new password hash in history
                user.PreviousPasswords.Add(new PreviousPasswords
                {
                    HashedPassword = _userManager.PasswordHasher.HashPassword(user, newPassword),
                    DateChanged = DateTime.UtcNow
                });

                // Keep only last 2 passwords
                if (user.PreviousPasswords.Count > 2)
                {
                    user.PreviousPasswords.RemoveAt(0); // Remove oldest password
                }

                await _userManager.UpdateAsync(user);
            }

            return result;
        }
    }
}
