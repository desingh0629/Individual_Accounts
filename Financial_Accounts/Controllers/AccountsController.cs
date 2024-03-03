using Financial_Accounts.Contracts;
using Financial_Accounts.DTOs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Financial_Accounts.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountsController(IUserInterface userInterface) : ControllerBase
    {
        [HttpPost("register")]
        public async Task<IActionResult> Register(UserDTO userDTO)
        {
            var response = await userInterface.CreateAccount(userDTO);
            return Ok(response);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginDTO login)
        {
            var response = await userInterface.LoginAccount(login);
            return Ok(response);
        }
    }
}
