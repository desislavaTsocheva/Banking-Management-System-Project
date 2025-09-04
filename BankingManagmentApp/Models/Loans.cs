namespace BankingManagmentApp.Models
{
    public class Loans
    {
        public int Id { get; set; }
        public string CustomerId { get; set; } 
        public string Type { get; set; }
        public decimal Amount { get; set; }
        public DateOnly Term { get; set; }
        public DateTime Date { get; set; } = DateTime.Now;
        public string Status { get; set; } = string.Empty;
        public decimal ApprovedAmount { get; set; }
        public DateTime ApprovalDate { get; set; } = DateTime.Now;
        public Customers Customer { get; set; }
        public ICollection<LoanRepayments> LoanRepayments { get; set; } = new List<LoanRepayments>();
        public ICollection<CreditAssessments> CreditAssessments { get; set; } = new List<CreditAssessments>(); // Добавена колекция за връзка
    }
}