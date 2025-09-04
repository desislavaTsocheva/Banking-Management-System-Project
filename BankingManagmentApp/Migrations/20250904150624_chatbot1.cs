using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BankingManagmentApp.Migrations
{
    /// <inheritdoc />
    public partial class chatbot1 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_ChatHistory_AspNetUsers_CustomersId",
                table: "ChatHistory");

            migrationBuilder.DropIndex(
                name: "IX_ChatHistory_CustomersId",
                table: "ChatHistory");

            migrationBuilder.DropColumn(
                name: "CustomersId",
                table: "ChatHistory");

            migrationBuilder.AddColumn<string>(
                name: "CustomerId",
                table: "ChatHistory",
                type: "nvarchar(450)",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_ChatHistory_CustomerId",
                table: "ChatHistory",
                column: "CustomerId");

            migrationBuilder.AddForeignKey(
                name: "FK_ChatHistory_AspNetUsers_CustomerId",
                table: "ChatHistory",
                column: "CustomerId",
                principalTable: "AspNetUsers",
                principalColumn: "Id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_ChatHistory_AspNetUsers_CustomerId",
                table: "ChatHistory");

            migrationBuilder.DropIndex(
                name: "IX_ChatHistory_CustomerId",
                table: "ChatHistory");

            migrationBuilder.DropColumn(
                name: "CustomerId",
                table: "ChatHistory");

            migrationBuilder.AddColumn<string>(
                name: "CustomersId",
                table: "ChatHistory",
                type: "nvarchar(450)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateIndex(
                name: "IX_ChatHistory_CustomersId",
                table: "ChatHistory",
                column: "CustomersId");

            migrationBuilder.AddForeignKey(
                name: "FK_ChatHistory_AspNetUsers_CustomersId",
                table: "ChatHistory",
                column: "CustomersId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
