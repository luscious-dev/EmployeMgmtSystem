using Blazored.LocalStorage;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ClientLibrary.Helpers
{
    public class LocalStorageService
    {
        private readonly ILocalStorageService _localStorageService;

        public LocalStorageService(ILocalStorageService localStorageService)
        {
            this._localStorageService = localStorageService;
        }

        private const string StorageKey = "authentication-token";
        public async Task<string> GetToken() => await _localStorageService.GetItemAsStringAsync(StorageKey);
        public async Task SetToken(string token) => await _localStorageService.SetItemAsStringAsync(StorageKey, token);
        public async Task RemoveToken() => await _localStorageService.RemoveItemAsync(StorageKey);
    }
}
