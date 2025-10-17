# LogCheckAI - Security Log Analysis

A comprehensive web application that combines React frontend with Flask backend to analyze security logs for anomaly detection, enhanced with AI-powered summary generation using Google's Generative AI API (Gemini 2.0 Flash).

## Features

- **User Authentication**: Secure signup/login with JWT tokens
- **File Upload**: Support for `.log` and `.txt` files (max 10MB)
- **CSV Parsing**: Intelligent parsing of structured log data
- **Multi-Layer Detection**: Rule-based analysis, ML algorithms (Isolation Forest), and AI-powered insights using Gemini 2.0 Flash
- **Threat Assessment**: Identifies high-risk activities and policy violations
- **Confidence Scoring**: Provides confidence levels for each detected anomaly
- **Smart Fallback**: Reliable backup system ensures professional output always

## 🏗️ Architecture

- **Frontend**: React + TypeScript with React Router
- **Backend**: Flask + Python with PostgreSQL
- **AI Integration**: Google Gemini 2.0 Flash API
- **Authentication**: JWT-based security
- **Fallback System**: Intelligent template-based summaries
- **Containerization**: Docker with docker-compose for easy deployment

## 🛠️ Setup Instructions

### Option 1: Docker Setup (Recommended)
```bash
# Clone the repository
git clone https://github.com/Tejaswi0707/LogCheckAI.git
cd LogCheckAI

# Create .env file with your configuration
echo "GEMINI_API_KEY=your_actual_api_key_here" > .env

# Start all services
docker-compose up -d

# Access the application
# Frontend: http://localhost
# Backend: http://localhost:5000
# Database: localhost:5432
```

### Option 2: Local Development Setup

#### Prerequisites
- Python 3.8+
- Node.js 16+
- PostgreSQL database

#### Backend Setup
```bash
cd backend
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
python app.py
```

#### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

## 🔧 Environment Variables

Create `.env` in the root directory:
```env
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=signup
DB_USER=postgres
DB_PASSWORD=your_password
JWT_SECRET_KEY=your-secret-key

# AI Integration (Required for AI features)
GEMINI_API_KEY=your_gemini_api_key
GEMINI_ENABLED=true

# Frontend (for production deployment only)
VITE_API_BASE_URL=http://localhost:5000
```

### Two-Tier AI Integration System

#### **Tier 1: Detection & Analysis (Primary)**
- **Rule-Based Detection**: High volume analysis, security threats, policy violations
- **Machine Learning**: Isolation Forest algorithm for outlier detection
- **Anomaly Identification**: Comprehensive security event detection

#### **Tier 2: AI Summarization & Fallback (Intelligence Layer)**
- **Gemini 2.0 Flash AI**: Google's latest AI model for intelligent security analysis
- **Professional SOC Reports**: Provides actionable intelligence for security analysts
- **Template Fallback**: Intelligent templates when AI is unavailable (always works)

### AI Integration
The system uses **Google Gemini 2.0 Flash API** to generate intelligent, professional security analysis summaries.

## API Endpoints

- `POST /signup` - User registration
- `POST /login` - User authentication
- `POST /process` - Upload and analyze logs
- `GET /anomaly-results/<filename>` - Get analysis results

## 🔍 Usage Examples

### Upload Security Logs
1. **Login** to your account
2. **Upload** a `.txt` or `.log` file (max 10MB)
3. **Wait** for secure analysis to complete
4. **Review** detected anomalies and AI-generated recommendations



---

**LogCheckAI** - Making security log analysis intelligent, reliable, and accessible! 🔍✨🤖

## 🚀 Key Benefits

- **AI-Powered Intelligence**: Professional security analysis using Gemini 2.0 Flash
- **100% Reliability**: Never fails - always provides analysis results
- **Clean Architecture**: Simple, maintainable code structure

---

