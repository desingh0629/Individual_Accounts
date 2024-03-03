using Financial_Accounts.Contracts;
using Financial_Accounts.Data;
using Financial_Accounts.DTOs;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using static Financial_Accounts.DTOs.ServiceResponses;

namespace Financial_Accounts
{
    public class UserService(UserManager<ApplicationUser> userManager,
                                         RoleManager<IdentityRole> roleManager,
                                          IConfiguration configuration) : IUserInterface
    {
        public async Task<GeneralResponse> CreateAccount(UserDTO userDTO)
        {
            if (userDTO is null) return new GeneralResponse(false, "Model is empty");

            var newUser = new ApplicationUser()
            {
                Name = userDTO.Name,
                Email = userDTO.Email,
                PasswordHash = userDTO.Password,
                UserName = userDTO.Name,
            };

            var user = await userManager.FindByEmailAsync(newUser.Email);
            if (user is not null) return new GeneralResponse(false, "User registered already");

            var createuser = await userManager.CreateAsync(newUser!, userDTO.Password);
            if (!createuser.Succeeded) return new GeneralResponse(false, "Error occured... please try again");

            //Assign default role : Admin to first register : rest is user

            var checkAdmin = await roleManager.FindByIdAsync("Admin");
            if (checkAdmin is null)
            {
                await roleManager.CreateAsync(new IdentityRole() { Name = "Admin" });
                await userManager.AddToRoleAsync(newUser, "Admin");
                return new GeneralResponse(true, "Account Created");
            }
            else
            {
                var checkUser = await roleManager.FindByIdAsync("User");
                if (checkUser is null)
                    await roleManager.CreateAsync(new IdentityRole() { Name = "User" });
                await userManager.AddToRoleAsync(newUser, "User");
                return new GeneralResponse(true, "Account Created");
            }

        }

        public async Task<LoginResponse> LoginAccount(LoginDTO loginDTO)
        {
            if (loginDTO is null) return new LoginResponse(false, null!, "Login container is empty");

            var getUser = await userManager.FindByEmailAsync(loginDTO.Email);
            if (getUser is null) return new LoginResponse(false, null!, "User not found");

            bool checkUserPassword = await userManager.CheckPasswordAsync(getUser, loginDTO.Password);
                if(!checkUserPassword)
                return new LoginResponse(false, null!, "Invalid email/password");

            var getUserRole = await userManager.GetRolesAsync(getUser);
            var userSession = new UserSession(getUser.Id, getUser.Name, getUser.Email, getUserRole.First());
            string token = GenerateToken(userSession);
            return new LoginResponse(true, token!, "Login completed");
        }

        private string GenerateToken(UserSession user)
        {
            var securitykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"]!));
            var credential = new SigningCredentials(securitykey, SecurityAlgorithms.HmacSha256);
            var userClaims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier , user.Id.ToString()),
                new Claim(ClaimTypes.Name , user.Name),
                new Claim(ClaimTypes.Email , user.Email),
                new Claim(ClaimTypes.Role , user.Role),
            };

            var token = new JwtSecurityToken(

                issuer: configuration["Jwt:Issuer"],
                audience: configuration["Jwt:Audiences"],
                claims: userClaims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: credential
                );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
