using BankingManagmentApp.Models;
using System.Collections.Generic;

namespace BankingManagmentApp.ViewModels
{
    public class ProfileVm
    {
        public Customers User { get; set; }

        public List<Accounts> Accounts { get; set; } = new();
        public List<Transactions> LastTransactions { get; set; } = new();

        public List<Loans> Loans { get; set; } = new();
        public List<LoanRepayments> UpcomingRepayments { get; set; } = new();

        public CreditAssessments? Credit { get; set; }
    }
}
