# LogCheckAI - System Design Diagrams

## 🏗️ Complete System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                           LogCheckAI System Architecture                                    │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   User Browser  │    │   React Frontend │    │  Flask Backend  │    │  PostgreSQL DB  │    │   AI Services   │
│   (Port 3000)   │◄──►│   (Port 3000)   │◄──►│   (Port 5000)   │◄──►│   (Port 5432)   │    │  (Gemini API)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🔄 Complete User Journey & Data Flow

### 1. Authentication Flow
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│    User     │───►│   Frontend  │───►│   Backend   │───►│ PostgreSQL  │───►│   JWT Token │
│  Signup/    │    │   (React)   │    │  (Flask)    │    │   Database  │    │  Generated  │
│   Login     │    │             │    │             │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │                   │
       │                   │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Browser   │◄───│   JWT Token │◄───│   Password  │◄───│   User Data │◄───│   Hash      │
│   Storage   │    │   Stored    │    │   Verified  │    │   Retrieved │    │   Verified  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

**API Endpoints Used:**
- `POST /signup` - User registration
- `POST /login` - User authentication  
- `POST /refresh` - Token refresh

### 2. File Upload & Processing Flow
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│    User     │───►│   Frontend  │───►│   Backend   │───►│   File      │───►│   CSV/Text  │
│  Selects    │    │   Dashboard │    │   Upload    │    │   Content   │    │   Parser    │
│    File     │    │             │    │   Handler   │    │   Read      │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │                   │
       │                   │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   File      │◄───│   FormData  │◄───│   File      │◄───│   UTF-8     │◄───│   Parsed    │
│   Selected  │    │   Created   │    │   Received  │    │   Decoded   │    │   Log Data  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

**API Endpoints Used:**
- `POST /upload-simple` - File upload (no auth required)
- `POST /process` - File processing (JWT auth required)

### 3. Anomaly Detection & AI Analysis Flow
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Parsed    │───►│   Rule-Based│───►│   ML-Based  │───►│   AI SOC    │───►│   Enhanced  │
│   Log Data  │    │   Detection │    │   Detection │    │   Generator │    │   SOC Report│
│             │    │             │    │(Isolation   │    │             │    │             │
│             │    │             │    │ Forest)     │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │                   │
       │                   │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   CSV Data  │    │   Security  │    │   Statistical│   │   Gemini AI │    │   Executive │
│   Structure │    │   Rules     │    │   Outliers  │   │   Integration│    │   Summary   │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

**Detection Methods:**
1. **Rule-Based Detection:**
   - High volume detection (3x above average)
   - Security threat indicators (malware, threats)
   - HTTP error codes (401, 403, 500)
   - Suspicious URL patterns
   - SSL certificate validity

2. **ML-Based Detection:**
   - Isolation Forest algorithm
   - Features: bytes sent/received, threat counts, SSL validity, time patterns
   - Contamination factor: 15%

3. **AI SOC Generation:**
   - Primary: Gemini 2.0 Flash AI
   - Fallback: Template-based system
   - Executive summary, risk assessment, recommendations

### 4. Results Display & Visualization Flow
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Backend   │───►│   Frontend  │───►│   Results   │───►│   Data      │───►│   User      │
│   Analysis  │    │   Storage   │    │   Page      │    │   Charts    │    │   Dashboard │
│   Complete  │    │(localStorage│    │   Rendering │    │   & Tables  │    │   View      │
│             │    │             │    │             │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │                   │
       │                   │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   SOC       │    │   JSON      │    │   React     │    │   Chart.js  │    │   Security  │
│   Report    │    │   Response  │    │   Components│    │   Integration│    │   Insights  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

## 🗄️ Database Schema & Data Flow

### PostgreSQL Database Structure
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Data Flow Through Database
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   User      │───►│   Password  │───►│   bcrypt    │───►│   Database  │
│   Input     │    │   Hashing   │    │   Hash      │    │   Storage   │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Email     │    │   Salt      │    │   Hashed    │    │   User      │
│   & Pass    │    │   Generated │    │   Password  │    │   Record    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

## 🔐 Security & Authentication Flow

### JWT Token Management
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Login     │───►│   Backend   │───►│   JWT       │───►│   Frontend  │
│   Success   │    │   Validation│    │   Generated │    │   Storage   │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │
       │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   User      │    │   Password  │    │   Access    │    │   Local     │
│   Creds     │    │   Verified  │    │   Token     │    │   Storage   │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘

Token Expiry:
- Access Token: 1 hour
- Refresh Token: 30 days
```

### Protected Route Flow
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   User      │───►│   Protected │───►│   JWT       │───►│   Backend   │
│   Access    │    │   Route     │    │   Validation│    │   API Call  │
│   Attempt   │    │   Component │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │
       │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Dashboard │    │   Auth      │    │   Token     │    │   Protected │
│   or        │    │   Check     │    │   Valid     │    │   Resource  │
│   Results   │    │             │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

## 🚀 Docker Container Architecture

### Service Dependencies & Networking
```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                    Docker Network: logcheckai_network                   │
└─────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │    Backend      │    │   PostgreSQL    │
│   Container     │    │   Container     │    │   Container     │
│   Port: 3000    │◄──►│   Port: 5000    │◄──►│   Port: 5432    │
│                 │    │                 │    │                 │
│   Dependencies: │    │   Dependencies: │    │   Dependencies: │
│   - Backend     │    │   - PostgreSQL  │    │   - None        │
│   - React      │    │   - AI Services  │    │   - Volume      │
│   - Vite       │    │   - Flask       │    │   - postgres_data│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Container Communication Flow
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Frontend  │───►│   Backend   │───►│ PostgreSQL │───►│   Volume    │
│   Build     │    │   Build     │    │   Pull      │    │   Mount     │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │
       │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Port      │    │   Port      │    │   Port      │    │   Data      │
│   3000      │    │   5000      │    │   5432      │    │   Persistence│
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

## 📊 API Endpoint Summary

### Public Endpoints (No Authentication)
```
POST /upload-simple     - File upload and processing
GET  /                 - Health check
```

### Protected Endpoints (JWT Authentication Required)
```
POST /process          - File processing with user context
POST /generate-soc-report - Generate SOC report for log data
POST /refresh          - Refresh JWT access token
```

### Authentication Endpoints
```
POST /signup           - User registration
POST /login            - User authentication
```

## 🔄 Complete Request-Response Flow Example

### File Upload & Analysis Request
```
1. User selects .txt/.log file in Dashboard
   ↓
2. Frontend creates FormData and sends POST to /upload-simple
   ↓
3. Backend receives file, reads content, detects file type
   ↓
4. If CSV format detected:
   - Parse CSV content
   - Apply rule-based anomaly detection
   - Apply ML-based anomaly detection (Isolation Forest)
   - Generate AI SOC report (Gemini AI or fallback)
   ↓
5. Backend returns comprehensive analysis including:
   - Parsed log entries
   - Anomaly detection results
   - SOC report
   - File metadata
   ↓
6. Frontend stores results in localStorage
   ↓
7. User redirected to AnomalyResults page
   ↓
8. Results displayed with tabs:
   - Log Analysis Summary
   - Anomaly Detection Details
   - Data Visualization & Analytics
```

## 🎯 Key Features & Capabilities

### Frontend Features
- **React-based SPA** with TypeScript
- **Protected Routes** with JWT authentication
- **File Upload** with validation (.txt, .log, max 10MB)
- **Real-time Processing** status updates
- **Tabbed Interface** for different analysis views
- **Responsive Design** with modern UI components
- **Data Visualization** with charts and tables
- **Pagination** for large datasets

### Backend Features
- **Flask REST API** with CORS support
- **JWT Authentication** with refresh tokens
- **PostgreSQL Database** for user management
- **File Processing** for CSV and text files
- **Multi-layer Anomaly Detection:**
  - Rule-based security analysis
  - ML-based outlier detection
  - AI-powered SOC report generation
- **Fallback Systems** for AI service failures
- **Comprehensive Error Handling**

### AI & ML Features
- **Gemini 2.0 Flash AI** integration for SOC reports
- **Isolation Forest** algorithm for anomaly detection
- **Template-based Fallback** when AI unavailable
- **Multi-feature Analysis:**
  - Network traffic patterns
  - User behavior analysis
  - Security threat correlation
  - Temporal pattern detection

### Security Features
- **Password Hashing** with bcrypt
- **JWT Token Management** with configurable expiry
- **Protected API Endpoints** with authentication middleware
- **Input Validation** and sanitization
- **CORS Configuration** for cross-origin requests
- **Environment Variable** configuration for secrets

## 🚀 Deployment & Scaling Considerations

### Current Architecture
- **Single Container** per service
- **Bridge Network** for inter-service communication
- **Volume Mounts** for data persistence
- **Port Mapping** for external access

### Potential Scaling Improvements
- **Load Balancing** for multiple backend instances
- **Database Connection Pooling** for high concurrency
- **Redis Cache** for session management
- **Message Queue** for async processing
- **Horizontal Scaling** with container orchestration
- **CDN** for static frontend assets
- **API Gateway** for request routing and rate limiting

This comprehensive system design shows LogCheckAI as a modern, scalable, and secure log analysis platform with AI-powered anomaly detection and SOC reporting capabilities.

