using BaseLibrary.DTOs;
using BaseLibrary.Responses;
using ClientLibrary.Services.Contracts;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ClientLibrary.Helpers
{
    public class CustomHttpHandler: DelegatingHandler
    {
        private readonly LocalStorageService _localStorageService;
        private readonly IUserAccountService _userAccountService;

        public CustomHttpHandler(LocalStorageService localStorageService, IUserAccountService userAccountService)
        {
            _localStorageService = localStorageService;
            _userAccountService = userAccountService;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var loginEndpoint = request.RequestUri.AbsolutePath.Contains("login");
            var registerEndpoint = request.RequestUri.AbsolutePath.Contains("register");
            var refreshEndpoint = request.RequestUri.AbsolutePath.Contains("refresh");

            if(loginEndpoint || registerEndpoint || refreshEndpoint)
                return await base.SendAsync(request, cancellationToken);

            var result = await base.SendAsync(request, cancellationToken);

            if(result.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                string token = request.Headers.Authorization?.Parameter ?? string.Empty;
                var stringToken = await _localStorageService.GetToken();
                if(stringToken is null) return result;

                var deserializedToken = Serializations.DeserializeJsonString<UserSession>(stringToken);

                if(deserializedToken?.RefreshToken is  null) return result;

                if (string.IsNullOrEmpty(token))
                {
                    request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                    return await base.SendAsync(request, cancellationToken);
                }

                var newJwtToken = await GetRefreshToken(deserializedToken.RefreshToken);

                if(string.IsNullOrEmpty(newJwtToken)) return result;

                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", newJwtToken);
                return await base.SendAsync(request, cancellationToken);
            }

            return result;
        }

        private async Task<string> GetRefreshToken(string token)
        {
            var result = await _userAccountService.RefreshTokenAsync(new RefreshToken { Token = token });
            string serializedToken = Serializations.SerializeObj(new UserSession()
            {
                Token = result.Token,
                RefreshToken = result.RefreshToken
            });

            await _localStorageService.SetToken(serializedToken);

            return result.Token;

        }
    }
}
