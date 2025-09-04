using System.ComponentModel.DataAnnotations;

public class TemplateAnswer
{
    [Key]
    public int Id { get; set; }

    [Required]
    public string Keyword { get; set; }

    [Required]
    public string AnswerText { get; set; }

    public string FunctionName { get; set; } 
}