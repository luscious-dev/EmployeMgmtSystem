using BaseLibrary.DTOs;
using Microsoft.AspNetCore.Components.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace ClientLibrary.Helpers
{
    public class CustomAuthenticationStateProvider : AuthenticationStateProvider
    {
        private readonly LocalStorageService _localStorageService;
        private readonly ClaimsPrincipal anonymous = new ClaimsPrincipal(new ClaimsIdentity());

        public CustomAuthenticationStateProvider(LocalStorageService localStorageService)
        {
            _localStorageService = localStorageService;
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var token = await _localStorageService.GetToken();

            if (token == null)
                return new AuthenticationState(anonymous);

            var tokenContent = Serializations.DeserializeJsonString<UserSession>(token);

            if (tokenContent == null)
                return new AuthenticationState(anonymous);

            var userClaims = DecryptClaims(tokenContent.Token);
            var claimsPrincipal = SetClaimsPrincipal(userClaims);

            return new AuthenticationState(claimsPrincipal);

        }

        public async Task UpdateAuthenticationState(UserSession session)
        {
            var claimsPrincipal = new ClaimsPrincipal();
            if(session.Token != null || session.RefreshToken != null)
            {
                var serializedSession = Serializations.SerializeObj<UserSession>(session);
                await _localStorageService.SetToken(serializedSession);
                var getUserClaims = DecryptClaims(session.Token);
                claimsPrincipal = SetClaimsPrincipal(getUserClaims);
            }
            else
            {
                await _localStorageService.RemoveToken();
            }

            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
        }

        private CustomUserClaims DecryptClaims(string tokenString)
        {
            var customClaims = new CustomUserClaims();
            var token = new JwtSecurityTokenHandler().ReadJwtToken(tokenString);

            var userId = token.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
            var name = token.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Name)?.Value;
            var role = token.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Role)?.Value;
            var email = token.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;

            return new CustomUserClaims(userId!, name!, role!, email!);
        }

        private ClaimsPrincipal SetClaimsPrincipal(CustomUserClaims claims)
        {
            var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(
                new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, claims.Id),
                    new Claim(ClaimTypes.Name, claims.Name),
                    new Claim(ClaimTypes.Role, claims.Role),
                    new Claim(ClaimTypes.Email, claims.Email),
                }, "jwtAuth"
            ));

            return claimsPrincipal;
        }
    }
}
