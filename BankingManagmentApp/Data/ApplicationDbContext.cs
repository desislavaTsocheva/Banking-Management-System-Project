using BankingManagmentApp.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace BankingManagmentApp.Data
{
    public class ApplicationDbContext : IdentityDbContext
    {
        public DbSet<Customers> Customers { get; set; }
        public DbSet<Accounts> Accounts { get; set; }
        public DbSet<Transactions> Transactions { get; set; }
        public DbSet<Loans> Loans { get; set; }
        public DbSet<LoanRepayments> LoanRepayments { get; set; }
        public DbSet<CreditAssessments> CreditAssessments { get; set; }
        public DbSet<TemplateAnswer> TemplateAnswer { get; set; }
        public DbSet<ChatHistory> ChatHistory { get; set; }

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
   
        }

    }
}
