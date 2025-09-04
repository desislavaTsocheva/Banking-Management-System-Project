using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BankingManagmentApp.Migrations
{
    /// <inheritdoc />
    public partial class Correct_2 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_CreditAssessments_Loans_LoansId",
                table: "CreditAssessments");

            migrationBuilder.DropForeignKey(
                name: "FK_LoanRepayments_Loans_LoansId",
                table: "LoanRepayments");

            migrationBuilder.DropIndex(
                name: "IX_LoanRepayments_LoansId",
                table: "LoanRepayments");

            migrationBuilder.DropIndex(
                name: "IX_CreditAssessments_LoansId",
                table: "CreditAssessments");

            migrationBuilder.DropColumn(
                name: "LoansId",
                table: "LoanRepayments");

            migrationBuilder.DropColumn(
                name: "LoansId",
                table: "CreditAssessments");

            migrationBuilder.AlterColumn<DateOnly>(
                name: "PaymentDate",
                table: "LoanRepayments",
                type: "date",
                nullable: true,
                oldClrType: typeof(DateOnly),
                oldType: "date");

            migrationBuilder.CreateIndex(
                name: "IX_LoanRepayments_LoanId",
                table: "LoanRepayments",
                column: "LoanId");

            migrationBuilder.CreateIndex(
                name: "IX_CreditAssessments_LoanId",
                table: "CreditAssessments",
                column: "LoanId");

            migrationBuilder.AddForeignKey(
                name: "FK_CreditAssessments_Loans_LoanId",
                table: "CreditAssessments",
                column: "LoanId",
                principalTable: "Loans",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_LoanRepayments_Loans_LoanId",
                table: "LoanRepayments",
                column: "LoanId",
                principalTable: "Loans",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_CreditAssessments_Loans_LoanId",
                table: "CreditAssessments");

            migrationBuilder.DropForeignKey(
                name: "FK_LoanRepayments_Loans_LoanId",
                table: "LoanRepayments");

            migrationBuilder.DropIndex(
                name: "IX_LoanRepayments_LoanId",
                table: "LoanRepayments");

            migrationBuilder.DropIndex(
                name: "IX_CreditAssessments_LoanId",
                table: "CreditAssessments");

            migrationBuilder.AlterColumn<DateOnly>(
                name: "PaymentDate",
                table: "LoanRepayments",
                type: "date",
                nullable: false,
                defaultValue: new DateOnly(1, 1, 1),
                oldClrType: typeof(DateOnly),
                oldType: "date",
                oldNullable: true);

            migrationBuilder.AddColumn<int>(
                name: "LoansId",
                table: "LoanRepayments",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "LoansId",
                table: "CreditAssessments",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateIndex(
                name: "IX_LoanRepayments_LoansId",
                table: "LoanRepayments",
                column: "LoansId");

            migrationBuilder.CreateIndex(
                name: "IX_CreditAssessments_LoansId",
                table: "CreditAssessments",
                column: "LoansId");

            migrationBuilder.AddForeignKey(
                name: "FK_CreditAssessments_Loans_LoansId",
                table: "CreditAssessments",
                column: "LoansId",
                principalTable: "Loans",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_LoanRepayments_Loans_LoansId",
                table: "LoanRepayments",
                column: "LoansId",
                principalTable: "Loans",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
