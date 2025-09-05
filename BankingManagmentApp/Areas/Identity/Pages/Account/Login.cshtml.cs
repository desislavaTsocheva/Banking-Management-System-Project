#nullable disable
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using SixLabors.Fonts;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;
using SixLabors.ImageSharp.Drawing.Processing;
using System.IO;
using BankingManagmentApp.Models;

namespace BankingManagmentApp.Areas.Identity.Pages.Account
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<Customers> _signInManager;
        private readonly UserManager<Customers> _userManager;
        private readonly ILogger<LoginModel> _logger;

        public LoginModel(SignInManager<Customers> signInManager, ILogger<LoginModel> logger, UserManager<Customers> userManager)
        {
            _signInManager = signInManager;
            _logger = logger;
            _userManager = userManager;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            [Required]
            [Display(Name = "CAPTCHA")]
            public string CaptchaInput { get; set; }

            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            returnUrl ??= Url.Content("~/");

            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            ReturnUrl = returnUrl;
        }

        // Handler за CAPTCHA изображение
        public IActionResult OnGetCaptcha()
        {
            var captchaText = new Random().Next(1000, 9999).ToString();
            HttpContext.Session.SetString("Captcha", captchaText);

            using var image = new Image<Rgba32>(120, 40);
            image.Mutate(ctx => ctx.Fill(Color.White));

            // Вземи системен шрифт
            Font font;
            try
            {
                font = SystemFonts.CreateFont("Arial", 20, FontStyle.Bold);
            }
            catch
            {
                font = SystemFonts.CreateFont("DejaVu Sans", 20, FontStyle.Bold); // fallback за Linux/macOS
            }

            image.Mutate(ctx => ctx.DrawText(captchaText, font, Color.Black, new PointF(10, 5)));

            using var ms = new MemoryStream();
            image.SaveAsPng(ms);
            return File(ms.ToArray(), "image/png");
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            if (ModelState.IsValid)
            {
                var captchaSession = HttpContext.Session.GetString("Captcha") ?? "";

                if (captchaSession != Input.CaptchaInput?.Trim())
                {
                    ModelState.AddModelError(string.Empty, "CAPTCHA е неправилна.");
                    return Page();
                }

                var user = await _userManager.FindByEmailAsync(Input.Email);

                if (user != null)
                {
                    var result = await _signInManager.PasswordSignInAsync(user.UserName, Input.Password, Input.RememberMe, lockoutOnFailure: false);

                    if (result.Succeeded)
                    {
                        _logger.LogInformation("User logged in.");
                        return LocalRedirect(returnUrl);
                    }
                    if (result.RequiresTwoFactor)
                    {
                        return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
                    }
                    if (result.IsLockedOut)
                    {
                        _logger.LogWarning("User account locked out.");
                        return RedirectToPage("./Lockout");
                    }
                }

                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return Page();
            }

            return Page();
        }
    }
}
