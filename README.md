# 🛡️ GRC Compliance Automation Platform

A Python-based Governance, Risk, and Compliance (GRC) platform designed to automate common compliance and audit workflows.

The application centralizes risk and audit findings, tracks remediation, generates compliance metrics, automates security questionnaire responses, and maps controls across frameworks such as ISO 27001 and NIST.

## 🎯 Project Objective

Compliance and audit teams often rely on scattered spreadsheets and repetitive manual processes to:

- Track audit findings and risks
- Monitor remediation deadlines
- Calculate and report risk severity
- Prepare compliance and security questionnaire responses
- Cross-reference controls between security frameworks
- Produce management-ready compliance reports

This project aims to bring these activities into one lightweight, Python-based GRC application.

## 🚀 Key Features

### 1. Risk & Audit Register
- Centralized finding and risk tracking
- Likelihood and impact scoring
- Automatic risk score calculation
- Risk severity classification
- Finding ownership
- Remediation due dates
- Status tracking
- Overdue remediation detection

### 2. Compliance Dashboard
- Total findings
- Open and closed findings
- Overdue remediation items
- High and critical risks
- Risk severity distribution
- Finding status metrics
- Compliance KPIs and KRIs

### 3. Security Questionnaire Response Generator
- Searchable response bank
- Standardized compliance responses
- Framework and control references
- Suggested supporting evidence
- Designed for ISO 27001/NIST-related questionnaires

### 4. Control Cross-Reference Mapper
- ISO 27001 control lookup
- NIST control lookup
- Cross-framework mappings
- Control descriptions
- Framework alignment information

### 5. Reporting
- Management-ready compliance reports
- Risk summaries
- Remediation status
- Overdue findings
- Compliance metrics

## 🏗️ Technology Stack

- **Python**
- **Streamlit**
- **Pandas**
- **SQLite**
- **Matplotlib**
- **OpenPyXL**

## 📐 Architecture


                 GRC COMPLIANCE AUTOMATION
                           │
                           ▼
                    Streamlit Interface
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
    Risk Register     Dashboard      Questionnaire
          │                │                │
          └────────────────┼────────────────┘
                           │
                           ▼
                    Control Mapper
                           │
                           ▼
                      SQLite DB
