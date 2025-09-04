namespace BankingManagmentApp.Models
{
    public class Accounts
    {
        public int Id { get; set; }
        public string CustomerId { get; set; }
        public string IBAN { get; set; }
        public string AccountType { get; set; }
        public decimal Balance { get; set; }
        public string Currency { get; set; }
        public DateTime CreateAt { get; set; } = DateTime.Now;
        public string Status { get; set; } = string.Empty;
        public Customers Customer { get; set; } 
        public ICollection<Transactions> Transactions { get; set; } = new List<Transactions>();
    }
}