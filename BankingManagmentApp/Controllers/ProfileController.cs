// Controllers/ProfileController.cs
using System;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using BankingManagmentApp.Data;
using BankingManagmentApp.Models;
using BankingManagmentApp.ViewModels;
using BankingManagmentApp.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace BankingManagmentApp.Controllers
{
    [Authorize]
    public class ProfileController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<Customers> _userManager;
        private readonly ICreditScoringService _scoring;

        public ProfileController(ApplicationDbContext db, UserManager<Customers> userManager, ICreditScoringService scoring)
        {
            _db = db;
            _userManager = userManager;
            _scoring = scoring;
        }

        // PROFILE DASHBOARD
        public async Task<IActionResult> Index()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Challenge();

            // Accounts на текущия user
            var accounts = await _db.Accounts
                .Where(a => a.CustomerId == user.Id)                // <-- FIX
                .OrderByDescending(a => a.CreateAt)
                .ToListAsync();

            var accountIds = accounts.Select(a => a.Id).ToList();

            var lastTx = await _db.Transactions
                .Where(t => accountIds.Contains(t.AccountsId))
                .OrderByDescending(t => t.Id)
                .Take(10)
                .ToListAsync();

            // Loans на текущия user
            var loans = await _db.Loans
                .Where(l => l.CustomerId == user.Id)                // <-- FIX
                .OrderByDescending(l => l.Date)
                .ToListAsync();

            var loanIds = loans.Select(l => l.Id).ToList();

            var upcomingRepayments = await _db.LoanRepayments
                .Where(r => loanIds.Contains(r.LoanId))
                .OrderBy(r => r.DueDate)
                .Take(5)
                .ToListAsync();

            // Реално изчисление на кредитния скор (без запис в БД)
            CreditAssessments? credit = null;
            var computed = await _scoring.ComputeAsync(user.Id);
            if (computed is not null)
            {
                credit = new CreditAssessments
                {
                    CreditScore = computed.Score,
                    RiskLevel = computed.RiskLevel,
                    Notes = computed.Notes
                };
            }

            var vm = new ProfileVm
            {
                User = user,
                Accounts = accounts,
                LastTransactions = lastTx,
                Loans = loans,
                UpcomingRepayments = upcomingRepayments,
                Credit = credit
            };

            return View(vm);
        }

        // ---- CSV EXPORTS ----

        [HttpGet]
        public async Task<IActionResult> ExportAccounts(int? accountId)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Challenge();

            var query = _db.Accounts
                .Where(a => a.CustomerId == user.Id);               // <-- FIX

            if (accountId.HasValue)
            {
                var belongs = await _db.Accounts.AnyAsync(a => a.Id == accountId.Value &&
                                                               a.CustomerId == user.Id); // <-- FIX
                if (!belongs) return Forbid();
                query = query.Where(a => a.Id == accountId.Value);
            }

            var accounts = await query.OrderBy(a => a.CreateAt).ToListAsync();

            var sb = new StringBuilder();
            sb.Append('\uFEFF'); // BOM за Excel
            sb.AppendLine("IBAN,Type,Currency,Balance,Status,Created");

            var inv = CultureInfo.InvariantCulture;

            static string Esc(string s) =>
                string.IsNullOrEmpty(s) ? "" :
                s.Contains(',') || s.Contains('"') || s.Contains('\n')
                    ? "\"" + s.Replace("\"", "\"\"") + "\""
                    : s;

            foreach (var a in accounts)
            {
                sb.AppendLine(string.Join(",",
                    Esc(a.IBAN),
                    Esc(a.AccountType),
                    Esc(a.Currency),
                    a.Balance.ToString("0.00", inv),
                    Esc(a.Status ?? ""),
                    a.CreateAt.ToString("yyyy-MM-dd HH:mm:ss", inv)
                ));
            }

            var bytes = Encoding.UTF8.GetBytes(sb.ToString());
            var fname = accountId.HasValue
                ? $"account_{accountId.Value}_{DateTime.UtcNow:yyyyMMdd_HHmmss}.csv"
                : $"accounts_all_{DateTime.UtcNow:yyyyMMdd_HHmmss}.csv";

            return File(bytes, "text/csv", fname);
        }

        [HttpGet]
        public async Task<IActionResult> ExportTransactions(int? accountId, DateTime? from, DateTime? to)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Challenge();

            var query = _db.Transactions
                .Include(t => t.Accounts)
                .Where(t => t.Accounts != null && t.Accounts.CustomerId == user.Id) // <-- FIX
                .AsQueryable();

            if (accountId.HasValue)
            {
                var belongs = await _db.Accounts.AnyAsync(a => a.Id == accountId.Value &&
                                                               a.CustomerId == user.Id); // <-- FIX
                if (!belongs) return Forbid();
                query = query.Where(t => t.AccountsId == accountId.Value);
            }

            DateOnly? fromD = from.HasValue ? DateOnly.FromDateTime(from.Value.Date) : null;
            DateOnly? toD = to.HasValue ? DateOnly.FromDateTime(to.Value.Date) : null;

            if (fromD.HasValue) query = query.Where(t => t.Date >= fromD.Value);
            if (toD.HasValue) query = query.Where(t => t.Date <= toD.Value);

            var list = await query
                .OrderBy(t => t.Date)
                .ThenBy(t => t.Id)
                .ToListAsync();

            var sb = new StringBuilder();
            sb.Append('\uFEFF');
            sb.AppendLine("Date,Type,Amount,Description,Reference,IBAN,Currency");

            var inv = CultureInfo.InvariantCulture;

            static string Esc(string s) =>
                string.IsNullOrEmpty(s) ? "" :
                s.Contains(',') || s.Contains('"') || s.Contains('\n')
                    ? "\"" + s.Replace("\"", "\"\"") + "\""
                    : s;

            foreach (var t in list)
            {
                sb.AppendLine(string.Join(",",
                    t.Date.ToString("yyyy-MM-dd", inv),
                    Esc(t.TransactionType),
                    t.Amount.ToString("0.00", inv),
                    Esc(t.Description ?? ""),
                    t.ReferenceNumber.ToString(inv),
                    Esc(t.Accounts?.IBAN ?? ""),
                    Esc(t.Accounts?.Currency ?? "")
                ));
            }

            var bytes = Encoding.UTF8.GetBytes(sb.ToString());
            var fname = "transactions";
            if (accountId.HasValue) fname += $"_acc{accountId.Value}";
            if (fromD.HasValue || toD.HasValue)
            {
                var f = fromD?.ToString("yyyyMMdd") ?? "min";
                var tt = toD?.ToString("yyyyMMdd") ?? "max";
                fname += $"_{f}-{tt}";
            }
            fname += $"_{DateTime.UtcNow:yyyyMMdd_HHmmss}.csv";

            return File(bytes, "text/csv", fname);
        }
    }
}
