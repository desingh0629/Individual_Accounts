using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Financial_Accounts.Data
{
    public class AppDbContext(DbContextOptions option) : IdentityDbContext<ApplicationUser>(option)
    {
    }
}
