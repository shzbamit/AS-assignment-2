using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Model
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        public string FullName { get; set; }

        [Required]
        public string EncryptedCreditCardNumber { get; set; } // Store encrypted credit card number

        [Required]
        public string Gender { get; set; } // "Male", "Female", "Other"

        [Required]
        public string MobileNo { get; set; }

        [Required]
        public string DeliveryAddress { get; set; }

        [Required]
        public string Photo { get; set; } // Store file path for the uploaded profile picture

        public string AboutMe { get; set; } // Allows all special characters

        // Add a list to store the last 2 password hashes
        public List<PreviousPasswords> PreviousPasswords { get; set; } = new List<PreviousPasswords>();

        public DateTime LastPasswordChangeDate { get; set; }
    }

    // Separate the PreviousPasswords class outside ApplicationUser
    public class PreviousPasswords
    {
        public string HashedPassword { get; set; }
        public DateTime DateChanged { get; set; }
    }

}
