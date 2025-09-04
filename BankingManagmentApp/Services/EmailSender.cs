using MailKit.Net.Smtp;
using Microsoft.AspNetCore.Identity.UI.Services;
using MimeKit;
using MailKit.Security;
using System.Threading.Tasks;

public class EmailSender : IEmailSender
{
    public async Task SendEmailAsync(string email, string subject, string htmlMessage)
    {
        var mimeMessage = new MimeMessage();
        mimeMessage.From.Add(new MailboxAddress("SuperAdmin", "superadmin@gmail.com"));
        mimeMessage.To.Add(MailboxAddress.Parse(email));
        mimeMessage.Subject = subject;

        mimeMessage.Body = new BodyBuilder { HtmlBody = htmlMessage }.ToMessageBody();

        using var client = new SmtpClient();
        await client.ConnectAsync("sandbox.smtp.mailtrap.io", 587, SecureSocketOptions.StartTls);

        // Replace with your actual Mailtrap username & password
        await client.AuthenticateAsync("a2315c47e7653e", "8da3ef272731be");

        await client.SendAsync(mimeMessage);
        await client.DisconnectAsync(true);
    }
}
