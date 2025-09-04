namespace BankingManagmentApp.Utilities
{
    public static class StringExtensions
    {
        public static string MaskIban(this string? iban)
        {
            if (string.IsNullOrWhiteSpace(iban)) return "****";
            var compact = new string(iban.Where(char.IsLetterOrDigit).ToArray());
            if (compact.Length <= 4) return "****";
            var last4 = compact[^4..];
            return $"**** **** **** {last4}";
        }
    }
}
