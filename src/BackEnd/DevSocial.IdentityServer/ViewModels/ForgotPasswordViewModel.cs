using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace DevSocial.IdentityServer.ViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required(ErrorMessage = "RequiredMessage")]
        [EmailAddress(ErrorMessage = "InvalidEmailAddress")]
        public string Email { get; set; }
        public string ReturnUrl { get; set; }
    }
}
