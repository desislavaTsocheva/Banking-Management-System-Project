using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using System.Net;
using System.Net.Mail;

namespace BankingManagmentApp.Services
{
    //public class EmailSender : IEmailSender
    //{
    //    private readonly IConfiguration _config;

    //    public EmailSender(IConfiguration config)
    //    {
    //        _config = config;
    //    }

    //    public async Task SendEmailAsync(string email, string subject, string htmlMessage)
    //    {
    //        using var client = new SmtpClient(_config["Smtp:Host"], int.Parse(_config["Smtp:Port"]))
    //        {
    //            Credentials = new NetworkCredential(_config["Smtp:Username"], _config["Smtp:Password"]),
    //            EnableSsl = true
    //        };

    //        var mailMessage = new MailMessage
    //        {
    //            From = new MailAddress(_config["Smtp:From"]),
    //            Subject = subject,
    //            Body = htmlMessage,
    //            IsBodyHtml = true
    //        };

    //        mailMessage.To.Add(email);
    //        await client.SendMailAsync(mailMessage);
    //    }
    //}
}

