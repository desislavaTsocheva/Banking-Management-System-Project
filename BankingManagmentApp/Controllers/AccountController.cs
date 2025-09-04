using Microsoft.AspNetCore.Mvc;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;

public class AccountController : Controller 
{
    public IActionResult CaptchaImage()
    {
        // Генерираме случайна 4-цифрена CAPTCHA
        var captchaText = new Random().Next(1000, 9999).ToString();
        HttpContext.Session.SetString("Captcha", captchaText);

        using var bmp = new Bitmap(120, 40);
        using var gfx = Graphics.FromImage(bmp);

        gfx.Clear(Color.White);
        using var font = new Font("Arial", 20, FontStyle.Bold);
        gfx.DrawString(captchaText, font, Brushes.Black, new PointF(10, 5));

        using var ms = new MemoryStream();
        bmp.Save(ms, ImageFormat.Png);
        return File(ms.ToArray(), "image/png");
    }
}