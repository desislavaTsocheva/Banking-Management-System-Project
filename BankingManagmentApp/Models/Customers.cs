using Microsoft.AspNetCore.Identity;

namespace BankingManagmentApp.Models
{
    public class Customers :IdentityUser 

    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Address { get; set; }
        public DateOnly DateOfBirth { get; set; }
        public DateTime CreateAt { get; set; } = DateTime.Now;
        public bool IsActive { get; set; }
        public ICollection<Accounts> Accounts { get; set; } = new List<Accounts>();
        public ICollection<Loans> Loans { get; set; } = new List<Loans>();
    }
}