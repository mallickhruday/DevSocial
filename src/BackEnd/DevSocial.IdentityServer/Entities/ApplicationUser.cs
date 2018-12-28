using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace DevSocial.IdentityServer.Entities
{
    public class ApplicationUser: IdentityUser
    {
        public string DisplayName { get; set; }
        public string TimeZoneId { get; set; }
        public string AvatarUrl { get; set; }
    }
}
