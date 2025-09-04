// Areas/Identity/Pages/Account/Manage/DownloadPersonalData.cshtml.cs
// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using BankingManagmentApp.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace BankingManagmentApp.Areas.Identity.Pages.Account.Manage
{
    public class DownloadPersonalDataModel : PageModel
    {
        private readonly UserManager<Customers> _userManager;
        private readonly ILogger<DownloadPersonalDataModel> _logger;

        public DownloadPersonalDataModel(
            UserManager<Customers> userManager,
            ILogger<DownloadPersonalDataModel> logger)
        {
            _userManager = userManager;
            _logger = logger;
        }

        public IActionResult OnGet()
        {
            // Показваме страницата, за да може да се натисне бутона за експорт
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            _logger.LogInformation("User with ID '{UserId}' requested a personal data export.", _userManager.GetUserId(User));

            var personalData = new Dictionary<string, string>();

            // [PersonalData] пропъртита (ако имаш такива атрибути върху Customers)
            var personalDataProps = typeof(Customers).GetProperties()
                .Where(prop => Attribute.IsDefined(prop, typeof(PersonalDataAttribute)));
            foreach (var p in personalDataProps)
            {
                personalData[p.Name] = p.GetValue(user)?.ToString() ?? "null";
            }

            // Профилни полета (включваме ги изрично)
            personalData["FirstName"] = user.FirstName ?? string.Empty;
            personalData["LastName"]  = user.LastName  ?? string.Empty;
            personalData["Address"]   = user.Address   ?? string.Empty;

            // DateOnly / DateOnly? – работи и в двата случая
            if (user.DateOfBirth is DateOnly dob && dob != default)
            {
                personalData["DateOfBirth"] = dob.ToString("yyyy-MM-dd");
            }

            // Външни логини
            var logins = await _userManager.GetLoginsAsync(user);
            foreach (var l in logins)
            {
                personalData[$"{l.LoginProvider} external login provider key"] = l.ProviderKey ?? string.Empty;
            }

            // Authenticator key (ако има)
            var authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
            if (!string.IsNullOrEmpty(authenticatorKey))
            {
                personalData["AuthenticatorKey"] = authenticatorKey;
            }

            Response.Headers.TryAdd("Content-Disposition", "attachment; filename=PersonalData.json");
            return new FileContentResult(JsonSerializer.SerializeToUtf8Bytes(personalData), "application/json");
        }
    }
}
