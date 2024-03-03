using Financial_Accounts.DTOs;
using static Financial_Accounts.DTOs.ServiceResponses;

namespace Financial_Accounts.Contracts
{
    public interface IUserInterface
    {
        Task<GeneralResponse> CreateAccount(UserDTO userDTO);
        Task<LoginResponse> LoginAccount(LoginDTO loginDTO);
    }
}
