using BaseLibrary.DTOs;
using BaseLibrary.Entities;
using BaseLibrary.Responses;
using BCrypt.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repository.Contracts;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Constants = ServerLibrary.Helpers.Constants;

namespace ServerLibrary.Repository.Implementations
{
    public class UserAccountRepository : IUserAccount
    {
        private readonly JwtSection _jwtSection;
        private readonly ApplicationDbContext _context;
        public UserAccountRepository(IOptions<JwtSection> jwtSection, ApplicationDbContext context)
        {
            _jwtSection = jwtSection.Value;
            _context = context;
        }

        public async Task<GeneralResponse> CreateAsync(Register user)
        {
            if (user is null) return new GeneralResponse(false, "Model is empty");

            var checkUser = await FindUserByEmail(user.Email);

            if (checkUser != null) return new GeneralResponse(false, "User registered already");

            // Save user
            var applicationUser = await AddToDatabase(new ApplicationUser
            {
                Fullname = user.Fullname,
                Email = user.Email,
                Password = BCrypt.Net.BCrypt.HashPassword(user.Password)
            });

            var checkAdminRole = await _context.SystemRoles.FirstOrDefaultAsync(_ => _.Name!.Equals(Constants.Admin));

            if (checkAdminRole is null)
            {
                var createAdminRole = await AddToDatabase(new SystemRole() { Name = Constants.Admin });
                await AddToDatabase(new UserRole() { RoleId = createAdminRole.Id, UserId = applicationUser.Id });
                return new GeneralResponse(true, "Account created");
            }

            var checkUserRole = await _context.SystemRoles.FirstOrDefaultAsync(_ => _.Name.Equals(Constants.User));
            SystemRole response = new();

            if (checkUserRole is null)
            {
                response = await AddToDatabase(new SystemRole()
                {
                    Name = Constants.User,
                });

                await AddToDatabase(new UserRole() { RoleId = response.Id, UserId = applicationUser.Id });
            }
            else
            {
                await AddToDatabase(new UserRole() { RoleId = checkUserRole.Id, UserId = applicationUser.Id });
            }

            return new GeneralResponse(true, "Account created");
        }

        public async Task<LoginResponse> SignInAsync(Login user)
        {
            if (user is null) return new LoginResponse(false, "Model is empty");

            var applicationUser = await FindUserByEmail(user.Email);
            if (applicationUser is null) return new LoginResponse(false, "User not found");

            if(!BCrypt.Net.BCrypt.Verify(user.Password, applicationUser.Password))
            {
                return new LoginResponse(false, "Email/Password not valid");
            }

            var getUserRole = await FindUserRole(applicationUser.Id);

            if (getUserRole is null) return new LoginResponse(false, "user role not found");

            var getRoleName = await FindRoleName(getUserRole.RoleId);

            if (getRoleName is null) return new LoginResponse(false, "role not found");

            string jwtToken = GenerateToken(applicationUser, getRoleName!.Name!);
            string refreshToken = GenerateRefreshToken();

            var userRefreshToken = await _context.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.UserId == applicationUser.Id);

            if(userRefreshToken is null)
            {
                _context.RefreshTokenInfos.Add(new RefreshTokenInfo
                {
                    UserId = applicationUser.Id,
                    Token = refreshToken
                });
            }
            else
            {
                userRefreshToken.Token = refreshToken;
            }

            await _context.SaveChangesAsync();

            return new LoginResponse(true, "Login successfully", jwtToken, refreshToken);
        }

        private async Task<ApplicationUser?> FindUserByEmail(string email)
        {
            var user = await _context.ApplicationUsers
                .Where(x => x.Email.ToLower().Equals(email.ToLower()))
                .FirstOrDefaultAsync();

            return user;
        }
        private async Task<UserRole> FindUserRole(int userId) => 
            await _context.UserRoles.FirstOrDefaultAsync(_ => _.UserId == userId);

        private async Task<SystemRole> FindRoleName(int roleId) =>
            await _context.SystemRoles.FirstOrDefaultAsync(_ => _.Id == roleId);

        private async Task<T> AddToDatabase<T>(T model)
        {
            var result = _context.Add(model!);
            await _context.SaveChangesAsync();
            return (T)result.Entity;
        }

        private string GenerateToken(ApplicationUser user, string role)
        {
            var key = Encoding.UTF8.GetBytes(_jwtSection.Key);
            var securityKey = new SymmetricSecurityKey(key);
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var userClaims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, role),
            };

            var token = new JwtSecurityToken(
                issuer: _jwtSection.Issuer,
                audience: _jwtSection.Audience,
                claims: userClaims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private static string GenerateRefreshToken()
        {
            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        }

        public async Task<LoginResponse> RefreshTokenAsync(RefreshToken token)
        {
            if (token is null)
                return new LoginResponse(false, "Model is empty");

            var findToken = await _context.RefreshTokenInfos
                .FirstOrDefaultAsync(_ => _.Token == token.Token);

            if (findToken is null)
                return new LoginResponse(false, "Refresh token is required");

            var user = await _context.ApplicationUsers.FirstOrDefaultAsync(_ => _.Id == findToken.UserId);

            if (user is null)
                return new LoginResponse(false, "Refresh token could not be generated because user not found");

            var userRole = await FindUserRole(user.Id);
            var roleName = await FindRoleName(userRole.RoleId);
            string jwtToken = GenerateToken(user, roleName.Name!);
            string refreshToken = GenerateRefreshToken();

            var updateRefreshToken = await _context.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.UserId == user.Id);

            if (updateRefreshToken is null)
                return new LoginResponse(false, "Refresh token could not be generated because user has not signed in");

            updateRefreshToken.Token = refreshToken;
            await _context.SaveChangesAsync();

            return new LoginResponse(true, "Token refreshed successfully", jwtToken, refreshToken);
        }
    }
}
