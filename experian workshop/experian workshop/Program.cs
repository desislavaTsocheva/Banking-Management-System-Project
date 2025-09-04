using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Text;
using System.Threading.Tasks;

namespace experian_workshop
{
    internal class Program
    {
        static void Main(string[] args)
        {
            
            var builder = WebApplication.CreateBuilder(args);
            var app = builder.Build();

            var users = new ConcurrentDictionary<string, User>(StringComparer.OrdinalIgnoreCase);

            record RegisterDto(string Email, string Password);
            record LoginDto(string Email, string Password);
            record Enable2FaDto(string Email);
            record Confirm2FaDto(string Email, string Code);
            record Login2FaDto(string Email, string Code);

         class User
        {

            public required string Email { get; set; }
            public required byte[] PasswordHash { get; set; }
            public required byte[] PasswordSalt { get; set; }
            public bool TwoFactorEnabled { get; set; }
            public byte[]? TwoFactorSecret { get; set; }
        }
        }

        static (byte[] hash, byte[] salt) HashPassword(string password)
        {
            var salt = RandomNumberGenerator.GetBytes(16);
            var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 100_000, HashAlgorithmName.SHA256, 32);
            return (hash, salt);
        }

        static bool VerifyPassword(string password, byte[] hash, byte[] salt)
        {
            var calc = Rfc2898DeriveBytes.Pbkdf2(password, salt, 100_000, HashAlgorithmName.SHA256, 32);
            return CryptographicOperations.FixedTimeEquals(calc, hash);
        }

        static string ToBase32(byte[] data)
        {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var sb = new StringBuilder();
            int buffer = 0, bitsLeft = 0;
            foreach (var b in data)
            {
                buffer = (buffer << 8) | b;
                bitsLeft += 8;
                while (bitsLeft >= 5)
                {
                    sb.Append(alphabet[(buffer >> (bitsLeft - 5)) & 31]);
                    bitsLeft -= 5;
                }
            }
            if (bitsLeft > 0) sb.Append(alphabet[(buffer << (5 - bitsLeft)) & 31]);
            return sb.ToString();
        }

        static int ComputeTotp(byte[] secret, long time, int step = 30, int digits = 6)
        {
            long counter = time / step;
            Span<byte> msg = stackalloc byte[8];
            for (int i = 7; i >= 0; i--) { msg[i] = (byte)(counter & 0xFF); counter >>= 8; }
            Span<byte> hmac = stackalloc byte[20];
            using var h = new HMACSHA1(secret);
            h.TryComputeHash(msg, hmac, out _);
            int off = hmac[^1] & 0xF;
            int bin = ((hmac[off] & 0x7F) << 24) | ((hmac[off + 1] & 0xFF) << 16) |
                      ((hmac[off + 2] & 0xFF) << 8) | (hmac[off + 3] & 0xFF);
            return bin % (int)Math.Pow(10, digits);
        }

        static bool VerifyTotp(byte[] secret, string code)
        {
            if (!int.TryParse(code, out var c)) return false;
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            for (int i = -1; i <= 1; i++)
                if (ComputeTotp(secret, now + i * 30) == c) return true;
            return false;
        }

        app.MapPost("/register", (RegisterDto dto) =>
{
    if (users.ContainsKey(dto.Email)) return Results.Conflict();
    var(hash, salt) = HashPassword(dto.Password);
        users[dto.Email] = new User { Email = dto.Email, PasswordHash = hash, PasswordSalt = salt
    };
    return Results.Ok();
});

app.MapPost("/login", (LoginDto dto) =>
{
    if (!users.TryGetValue(dto.Email, out var u) || !VerifyPassword(dto.Password, u.PasswordHash, u.PasswordSalt))
        return Results.Unauthorized();
    return u.TwoFactorEnabled ? Results.BadRequest(new { twoFactor = true }) : Results.Ok(new { message = "Success" });
});

app.MapPost("/enable-2fa", (Enable2FaDto dto) =>
{
    if (!users.TryGetValue(dto.Email, out var u)) return Results.NotFound();
    var secret = RandomNumberGenerator.GetBytes(20);
    u.TwoFactorSecret = secret;
    var s = ToBase32(secret);
    return Results.Ok(new { secret = s, uri = $"otpauth://totp/App:{u.Email}?secret={s}&issuer=App" });
});

app.MapPost("/confirm-2fa", (Confirm2FaDto dto) =>
{
    if (!users.TryGetValue(dto.Email, out var u) || u.TwoFactorSecret is null) return Results.BadRequest();
    if (!VerifyTotp(u.TwoFactorSecret, dto.Code)) return Results.BadRequest(new { error = "Invalid code" });
    u.TwoFactorEnabled = true;
    return Results.Ok();
});

app.MapPost("/login-2fa", (Login2FaDto dto) =>
{
    if (!users.TryGetValue(dto.Email, out var u) || u.TwoFactorSecret is null) return Results.BadRequest();
    return VerifyTotp(u.TwoFactorSecret, dto.Code) ? Results.Ok(new { message = "2FA OK" }) : Results.Unauthorized();
});

app.Run();























































































































































        }
    }
}
