using System.ComponentModel.DataAnnotations;
using System;

namespace AspNetIdentityLocal.Models
{
    public class RegisterRequest
    {
        [EmailAddress]
        [Required]
        public string Email {get;set;}

        [DataType(DataType.Password)]
        [Required]
        public string Password {get;set;}

        [DataType(DataType.Password)]
        [Compare("Password")]
        [Required]
        public string ConfirmPassword {get;set;}

        [Required]
        public string FirstName {get;set;}

        [Required]
        public string LastName {get;set;}
    }

    public class AuthRequest
    {
        [EmailAddress]
        [Required]
        public string UserName {get;set;}

        [DataType(DataType.Password)]
        [Required]
        public string Password {get;set;}
        
        [Required]
        public string AudienceKey {get;set;}
    }

    public class AuthResponse
    {
        public string Token {get;set;}
        public DateTime Expiration {get;set;}
    }
}