#nullable disable
using System;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using BankingManagmentApp.Models;              // Customers
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace BankingManagmentApp.Areas.Identity.Pages.Account.Manage
{
    public class IndexModel : PageModel
    {
        private readonly UserManager<Customers> _userManager;
        private readonly SignInManager<Customers> _signInManager;

        public IndexModel(UserManager<Customers> userManager, SignInManager<Customers> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        public string Username { get; set; }

        [TempData]
        public string StatusMessage { get; set; }

        [BindProperty]
        public InputModel Input { get; set; }

        public class InputModel
        {
            [Phone]
            [Display(Name = "Phone number")]
            public string PhoneNumber { get; set; }

            [Required]
            [Display(Name = "First name")]
            public string FirstName { get; set; }

            [Required]
            [Display(Name = "Last name")]
            public string LastName { get; set; }

            [Display(Name = "Address")]
            public string Address { get; set; }

            [DataType(DataType.Date)]
            [Display(Name = "Date of birth")]
            public DateOnly? DateOfBirth { get; set; }   
        }

        private async Task LoadAsync(Customers user)
        {
            Username = await _userManager.GetUserNameAsync(user);

            Input = new InputModel
            {
                PhoneNumber = await _userManager.GetPhoneNumberAsync(user),
                FirstName   = user.FirstName,
                LastName    = user.LastName,
                Address     = user.Address,
                DateOfBirth = user.DateOfBirth    
            };
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");

            await LoadAsync(user);
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");

            if (!ModelState.IsValid)
            {
                await LoadAsync(user);
                return Page();
            }

            var currentPhone = await _userManager.GetPhoneNumberAsync(user);
            if (Input.PhoneNumber != currentPhone)
            {
                var setPhoneResult = await _userManager.SetPhoneNumberAsync(user, Input.PhoneNumber);
                if (!setPhoneResult.Succeeded)
                {
                    StatusMessage = "Unexpected error when trying to set phone number.";
                    return RedirectToPage();
                }
            }

            // Полетата от Customers
            user.FirstName   = Input.FirstName?.Trim();
            user.LastName    = Input.LastName?.Trim();
            user.Address     = Input.Address?.Trim();
            user.DateOfBirth = (DateOnly)Input.DateOfBirth;   

            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                foreach (var e in updateResult.Errors)
                    ModelState.AddModelError(string.Empty, e.Description);

                await LoadAsync(user);
                return Page();
            }

            await _signInManager.RefreshSignInAsync(user);
            StatusMessage = "Your profile has been updated";
            return RedirectToPage();
        }
    }
}
