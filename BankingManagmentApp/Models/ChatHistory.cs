using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using BankingManagmentApp.Models;
using Microsoft.AspNetCore.Identity;

public class ChatHistory
{
    [Key]
    public int Id { get; set; }

    public string Sender { get; set; } // "user" or "bot"

    public string Message { get; set; }

    public DateTime Timestamp { get; set; }

    public string CustomerId { get; set; } // Или UserId, ако се свързвате с AspNetUsers
    [ForeignKey("CustomerId")]
    public Customers Customer { get; set; }
}