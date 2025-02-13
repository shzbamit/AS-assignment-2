using System.ComponentModel.DataAnnotations;

namespace WebApplication1.ViewModels
{
    public class Register
    {
        [Required]
        [Display(Name = "Full Name")]
        public string FullName { get; set; }

        [Required]
        [DataType(DataType.CreditCard)]
        [Display(Name = "Credit Card No")]
        public string CreditCardNumber { get; set; } // Will be encrypted before saving

        [Required]
        [Display(Name = "Gender")]
        public string Gender { get; set; } // Can be "Male", "Female", "Other"

        [Required]
        [Phone]
        [Display(Name = "Mobile No")]
        public string MobileNo { get; set; }

        [Required]
        [Display(Name = "Delivery Address")]
        public string DeliveryAddress { get; set; }

        [Required]
        [EmailAddress]
        [Display(Name = "Email Address")]
        public string Email { get; set; } // Must be unique

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        [MinLength(12, ErrorMessage = "Password must be at least 12 characters long.")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{12,}$",
            ErrorMessage = "Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character.")]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm Password")]
        [Compare("Password", ErrorMessage = "Passwords do not match.")]
        public string ConfirmPassword { get; set; }

        [Display(Name = "About Me")]
        public string AboutMe { get; set; } // Allows all special characters
    }

}
