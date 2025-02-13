using Microsoft.AspNetCore.DataProtection;
using System;
using System.Text;

namespace WebApplication1.Services
{
    public class EncryptionService
    {
        private readonly IDataProtectionProvider _dataProtectionProvider;
        private readonly string _purpose = "CreditCardEncryption";

        public EncryptionService(IDataProtectionProvider dataProtectionProvider)
        {
            _dataProtectionProvider = dataProtectionProvider;
        }

        // Encrypt the credit card number
        public string Encrypt(string creditCardNumber)
        {
            var protector = _dataProtectionProvider.CreateProtector(_purpose);
            var encryptedBytes = protector.Protect(Encoding.UTF8.GetBytes(creditCardNumber));
            return Convert.ToBase64String(encryptedBytes);
        }

        // Decrypt the credit card number
        public string Decrypt(string encryptedCreditCardNumber)
        {
            var protector = _dataProtectionProvider.CreateProtector(_purpose);
            var decryptedBytes = protector.Unprotect(Convert.FromBase64String(encryptedCreditCardNumber));
            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}
