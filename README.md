Experian Workshop
# Banking Management System (BMS)

[![.NET](https://img.shields.io/badge/.NET-7/8-512BD4?logo=dotnet\&logoColor=white)](#tech-stack)
[![C#](https://img.shields.io/badge/C%23-10/11-239120?logo=csharp\&logoColor=white)](#tech-stack)
[![ASP.NET MVC](https://img.shields.io/badge/ASP.NET-MVC-informational)](#architecture)
[![MySQL](https://img.shields.io/badge/DB-MySQL-4479A1?logo=mysql\&logoColor=white)](#database)
[![Bootstrap](https://img.shields.io/badge/UI-Bootstrap-7952B3?logo=bootstrap\&logoColor=white)](#frontend)
[![Tests](https://img.shields.io/badge/Tests-Unit-brightgreen)](#tests)
[![License](https://img.shields.io/badge/License-MIT-blue)](#license)

A web platform created as part of the **Experian Software Development Workshop**, designed to streamline banking operations with secure account management, loan processing, and analytics. The workshop brief targeted **AI-assisted credit scoring, chatbots for customer support, and predictive analytics** for reporting. 

---

## Table of Contents

* [Features](#features)
* [Architecture](#architecture)
* [Tech Stack](#tech-stack)
* [Getting Started](#getting-started)
* [Configuration](#configuration)
* [Database & Migrations](#database--migrations)
* [Running the App](#running-the-app)
* [AI Components](#ai-components)
* [Testing](#tests)
* [Project Structure](#project-structure)
* [Contributing](#contributing)
* [License](#license)

---

## Features

### 1) Customer Account Management

* Create customer profiles & accounts
* View balances, statements, transaction history
* Basic KYC fields & validation
* (AI option) **Chatbot** for common inquiries (balance, history, FAQs) 

### 2) Loans & Mortgage Processing

* Loan application submission & tracking
* Workflow: submit → score → approve/decline
* **AI-assisted credit scoring** & risk level suggestion (see [AI Components](#ai-components)) 

### 3) Financial Analytics & Reporting

* Dashboards (KPIs, volumes, approvals)
* Exportable reports
* **Predictive analytics** hooks for trend forecasting (see [AI Components](#ai-components)) 

---

## Architecture

```
ASP.NET MVC (Controllers/Views)
      │
      ├── Application Services (Domain logic, validation)
      │       └── Credit Scoring Service 
      │
      ├── Data Access Layer (Entity Framework)
      │       └── MySQL (InnoDB)
      │
      └── Web UI (Bootstrap, HTML/CSS/JS)
```

* **Layered**: MVC controllers → services → EF repositories
* **Configurations** via `appsettings.json` & environment variables
* **Unit tests** target services & scoring logic

---

## Tech Stack

* **Back-end**: C#, ASP.NET MVC, ASP.NET Core, Entity Framework
* **Front-end**: HTML5, CSS3, JavaScript, Bootstrap
* **Database**: MySQL
* **AI**: ML.NET (K-Means clustering), simple rule fallback

---

## Getting Started

### Prerequisites

* .NET 7 or 8 SDK
* MySQL 8.x

### Clone

```bash
git clone https://github.com/yovanabozhilov/Banking-Management-System-Project.git
code .
```

---

## Configuration

Create or update `appsettings.Development.json`with your own Mailtrap username and password:

```json
"SmtpSettings": {
    "Server": "sandbox.smtp.mailtrap.io",
    "Port": 2525,
    "Username": "<your-mailtrap-username>",
    "Password": "<your-mailtrap-password>"
  },
```

---

## Database & Migrations

```bash
# Restore & build
dotnet restore
dotnet build

# Create DB schema
dotnet ef database update

# Add a new migration (when you change models)
dotnet ef migrations add <MigrationName>
dotnet ef database update
```

---

## Running the App

```bash
dotnet run
```
Or with an explicit connection string
```bash
ConnectionStrings__DefaultConnection='Server=localhost;Database=BankingManagmentSystem;User Id=...;Password=...;SslMode=None' \
dotnet run
```

Open `https://localhost:5001` (or the port printed in console).

---

## AI Components

This project includes **hooks for AI**, aligned with the workshop brief: 

1. **Credit Scoring Service**

* Input: user profile features + aggregates from transaction history
* Pipeline:

  * Feature engineering (income, utilization, on-time ratio, clusters)
  * **Clustering (k-means)** to assign behavioral segment
  * Rule fallback for transparent bands if model unavailable
* Output: `{ Score, RiskLevel, Notes }`

2. **Chatbot (Customer Support)**

* Endpoint stub to integrate an FAQ/transaction-status bot 
* Scope: balances, last transactions, loan status

3. **Predictive Analytics**

* Forecast loan volumes / default rates 
* Display in admin dashboard as a simple line chart

---

## Tests

The test file **Models/ML/CreditFeaturesTests.cs** reads DB settings from env vars.  
Set **your own** values before `dotnet test`:

```md
`TEST_SQLSERVER_HOST`, `TEST_SQLSERVER_PORT`, `TEST_SQLSERVER_USER`, `TEST_SQLSERVER_PASS`
```

Then run: 

```bash
dotnet test
```
---

## Project Structure

```
Banking-Management-System-Project/
├─ BankingManagmentApp/
│  ├─ Areas/
│  ├─ Configuration/
│  ├─ Controllers/
│  ├─ Models/
│  ├─ Services/
│  ├─ Utilities/          
│  ├─ Data/
│  ├─ ViewModels/                
│  ├─ Views/                 
│  ├─ wwwroot/               
│  ├─ appsettings.json
│  └─ Program.cs 
├─ BankingManagmentApp.Tests/
├─ LICENCE                      
└─ README.md
```

---

## Contributing

PRs and issues are welcome. Please:

1. Create a feature branch
2. Add/adjust unit tests
3. Open a PR with a clear description & screenshots if UI changes

---

## License

MIT — see `LICENSE` file.

---

