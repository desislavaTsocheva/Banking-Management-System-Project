// Services/Credit/CreditScoringService.cs
using System;
using System.Linq;
using System.Threading.Tasks;
using BankingManagmentApp.Data;
using Microsoft.EntityFrameworkCore;

namespace BankingManagmentApp.Services
{
    public class CreditScoreResult
    {
        public int Score { get; set; }
        public int RiskLevel { get; set; } // 1..4
        public string Notes { get; set; } = string.Empty;
    }

    public interface ICreditScoringService
    {
        Task<CreditScoreResult?> ComputeAsync(string userId);
    }

    public class CreditScoringService : ICreditScoringService
    {
        private readonly ApplicationDbContext _db;

        public CreditScoringService(ApplicationDbContext db)
        {
            _db = db;
        }

        public async Task<CreditScoreResult?> ComputeAsync(string userId)
        {
            // Проверка дали изобщо има данни за този user
            var hasAccounts = await _db.Accounts.AnyAsync(a => a.CustomerId == userId);

            var loanIds = await _db.Loans
                .Where(l => l.CustomerId == userId)
                .Select(l => l.Id)
                .ToListAsync();

            var hasLoans = loanIds.Any();
            var hasRepayments = hasLoans &&
                await _db.LoanRepayments.AnyAsync(r => loanIds.Contains(r.LoanId));

            if (!hasAccounts && !hasLoans && !hasRepayments)
                return null; // няма реални данни → няма скор

            // --- текущата ти логика за скор-а ---
            var reps = await _db.LoanRepayments
                .Where(r => loanIds.Contains(r.LoanId))
                .ToListAsync();

            var totalRep = reps.Count;
            var paid = reps.Count(r => r.Status != null && r.Status.Equals("Paid", StringComparison.OrdinalIgnoreCase));
            var overdue = reps.Count(r => r.Status != null && r.Status.Equals("Overdue", StringComparison.OrdinalIgnoreCase));

            var accounts = await _db.Accounts
                .Where(a => a.CustomerId == userId)
                .ToListAsync();

            var totalBalance = accounts.Sum(a => a.Balance);

            decimal score = 650m;

            if (totalRep > 0)
            {
                decimal onTimeRatio = (decimal)paid / totalRep;
                decimal overdueRatio = (decimal)overdue / totalRep;

                score += (onTimeRatio - 0.5m) * 200m; // +/-100
                score -= overdueRatio * 250m;         // до -250
            }

            if (totalBalance > 5000m) score += 20m;
            if (totalBalance < 0m) score -= 30m;

            if (loanIds.Count == 0) score += 10m;

            var final = (int)Math.Clamp((double)score, 300, 850);

            var risk =
                final >= 720 ? 1 :
                final >= 660 ? 2 :
                final >= 600 ? 3 : 4;

            var notes =
                $"Loans: {loanIds.Count}, Repayments: {totalRep}, Paid: {paid}, Overdue: {overdue}, Balance: {totalBalance:0.00}";

            return new CreditScoreResult
            {
                Score = final,
                RiskLevel = risk,
                Notes = notes
            };
        }

    }
}
