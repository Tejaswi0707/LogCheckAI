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

## 🌐 Deployment Guide

### Deploy to Railway (Recommended)

Railway provides free hosting with PostgreSQL database included.

#### Step 1: Prepare Your Code
Your code is already configured for deployment with environment-based backend URLs.

#### Step 2: Deploy to Railway

1. **Sign up at [Railway](https://railway.app)** and connect your GitHub account

2. **Create New Project**
   - Click "New Project" → "Deploy from GitHub repo"
   - Select `LogCheckAI` repository

3. **Add PostgreSQL Database**
   - Click "+ New" → "Database" → "PostgreSQL"
   - Railway will automatically create and configure the database

4. **Configure Backend Service**
   - Railway auto-detects your backend from `backend/` directory
   - Add these environment variables in Railway dashboard:
     ```
     GEMINI_API_KEY=your_actual_gemini_api_key
     JWT_SECRET_KEY=your_secure_jwt_secret
     DB_HOST=${{Postgres.RAILWAY_PRIVATE_DOMAIN}}
     DB_PORT=5432
     DB_NAME=${{Postgres.PGDATABASE}}
     DB_USER=${{Postgres.PGUSER}}
     DB_PASSWORD=${{Postgres.PGPASSWORD}}
     ```

5. **Configure Frontend Service**
   - Railway auto-detects your frontend from `frontend/` directory
   - Add this environment variable:
     ```
     VITE_API_BASE_URL=https://your-backend-url.railway.app
     ```
   - Replace `your-backend-url` with the actual URL Railway provides for your backend

6. **Deploy**
   - Railway will automatically build and deploy both services
   - Wait 5-10 minutes for the build to complete
   - You'll get two live URLs (one for frontend, one for backend)

#### Step 3: Get Your Gemini API Key
- Visit [Google AI Studio](https://aistudio.google.com/app/apikey)
- Create a new API key
- Add it to your Railway backend environment variables

#### Deployment Time
- First deployment: ~15-20 minutes
- Subsequent deployments: Auto-deploy on git push (~5 minutes)

### Alternative Deployment Options

#### Render.com
- Deploy backend as "Web Service"
- Deploy frontend as "Static Site"
- Add PostgreSQL from Render dashboard

#### Vercel (Frontend) + Railway (Backend + DB)
- Deploy frontend to Vercel for optimal performance
- Deploy backend and database to Railway
- Configure `VITE_API_BASE_URL` in Vercel environment variables
