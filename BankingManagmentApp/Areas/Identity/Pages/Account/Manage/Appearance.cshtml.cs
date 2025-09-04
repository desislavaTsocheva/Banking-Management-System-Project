// Areas/Identity/Pages/Account/Manage/Appearance.cshtml.cs
#nullable disable
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Http;

namespace BankingManagmentApp.Areas.Identity.Pages.Account.Manage
{
    public class AppearanceModel : PageModel
    {
        [TempData]
        public string StatusMessage { get; set; }

        [BindProperty]
        public InputModel Input { get; set; }

        public class InputModel
        {
            [Required]
            public string Mode { get; set; } // "light" | "dark" | "system"
        }

        public void OnGet()
        {
            var current = Request.Cookies["theme"] ?? "system";
            Input = new InputModel { Mode = current };
        }

        public IActionResult OnPost()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Запиши глобално cookie-то за 1 година
            var opts = new CookieOptions
            {
                Path = "/",
                Expires = DateTimeOffset.UtcNow.AddYears(1),
                SameSite = SameSiteMode.Lax,
                Secure = Request.IsHttps // да не чупи на http локално
            };
            Response.Cookies.Append("theme", Input.Mode, opts);

            StatusMessage = "Appearance preference saved.";
            return RedirectToPage();
        }
    }
}
