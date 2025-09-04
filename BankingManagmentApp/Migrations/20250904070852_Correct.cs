using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BankingManagmentApp.Migrations
{
    /// <inheritdoc />
    public partial class Correct : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Accounts_AspNetUsers_CustomerId1",
                table: "Accounts");

            migrationBuilder.DropForeignKey(
                name: "FK_Loans_AspNetUsers_CustomerId1",
                table: "Loans");

            migrationBuilder.DropIndex(
                name: "IX_Loans_CustomerId1",
                table: "Loans");

            migrationBuilder.DropIndex(
                name: "IX_Accounts_CustomerId1",
                table: "Accounts");

            migrationBuilder.DropColumn(
                name: "CustomerId1",
                table: "Loans");

            migrationBuilder.DropColumn(
                name: "CustomerId1",
                table: "Accounts");

            migrationBuilder.AlterColumn<string>(
                name: "CustomerId",
                table: "Loans",
                type: "nvarchar(450)",
                nullable: false,
                oldClrType: typeof(int),
                oldType: "int");

            migrationBuilder.AlterColumn<string>(
                name: "CustomerId",
                table: "Accounts",
                type: "nvarchar(450)",
                nullable: false,
                oldClrType: typeof(int),
                oldType: "int");

            migrationBuilder.CreateIndex(
                name: "IX_Loans_CustomerId",
                table: "Loans",
                column: "CustomerId");

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_CustomerId",
                table: "Accounts",
                column: "CustomerId");

            migrationBuilder.AddForeignKey(
                name: "FK_Accounts_AspNetUsers_CustomerId",
                table: "Accounts",
                column: "CustomerId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_Loans_AspNetUsers_CustomerId",
                table: "Loans",
                column: "CustomerId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Accounts_AspNetUsers_CustomerId",
                table: "Accounts");

            migrationBuilder.DropForeignKey(
                name: "FK_Loans_AspNetUsers_CustomerId",
                table: "Loans");

            migrationBuilder.DropIndex(
                name: "IX_Loans_CustomerId",
                table: "Loans");

            migrationBuilder.DropIndex(
                name: "IX_Accounts_CustomerId",
                table: "Accounts");

            migrationBuilder.AlterColumn<int>(
                name: "CustomerId",
                table: "Loans",
                type: "int",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(450)");

            migrationBuilder.AddColumn<string>(
                name: "CustomerId1",
                table: "Loans",
                type: "nvarchar(450)",
                nullable: true);

            migrationBuilder.AlterColumn<int>(
                name: "CustomerId",
                table: "Accounts",
                type: "int",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(450)");

            migrationBuilder.AddColumn<string>(
                name: "CustomerId1",
                table: "Accounts",
                type: "nvarchar(450)",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Loans_CustomerId1",
                table: "Loans",
                column: "CustomerId1");

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_CustomerId1",
                table: "Accounts",
                column: "CustomerId1");

            migrationBuilder.AddForeignKey(
                name: "FK_Accounts_AspNetUsers_CustomerId1",
                table: "Accounts",
                column: "CustomerId1",
                principalTable: "AspNetUsers",
                principalColumn: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_Loans_AspNetUsers_CustomerId1",
                table: "Loans",
                column: "CustomerId1",
                principalTable: "AspNetUsers",
                principalColumn: "Id");
        }
    }
}
