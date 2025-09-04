namespace BankingManagmentApp.Models
{
    public class LoanRepayments
    {
        public int Id { get; set; }

        public int LoanId { get; set; }   // FK
        public Loans Loan { get; set; }

        public DateOnly DueDate { get; set; }
        public decimal AmountDue { get; set; }
        public decimal AmountPaid { get; set; }
        public DateOnly? PaymentDate { get; set; } 
        public string Status { get; set; }
    }

}
