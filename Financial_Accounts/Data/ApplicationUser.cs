using Microsoft.AspNetCore.Identity;

namespace Financial_Accounts.Data
{
    public class ApplicationUser : IdentityUser
    {
        public string Name { get; set; }
    }
}
