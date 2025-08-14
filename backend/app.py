from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from dotenv import load_dotenv
import psycopg2
import bcrypt
import os
import csv
import json
from datetime import timedelta
import re
from collections import defaultdict, Counter

# Import enhanced AI SOC generator
try:
    from enhanced_ai_soc import EnhancedAISOCGenerator
    AI_AVAILABLE = True
    ai_generator = EnhancedAISOCGenerator()
    enhanced_ai_generator = EnhancedAISOCGenerator()  # Separate instance for fallback
except ImportError as e:
    AI_AVAILABLE = False
    ai_generator = None
    enhanced_ai_generator = None

# Simple explanation generator

load_dotenv()

# Simple explanation generator
def generate_simple_explanation(anomaly_type, details):
    """Generate simple, clear anomaly explanations"""
    explanations = {
        'high_volume': f"🚨 High volume: {details}",
        'security_threat': f"🛡️ Security threat: {details}",
        'http_error': f"❌ HTTP error: {details}",
        'suspicious_url': f"⚠️ Suspicious URL: {details}"
    }
    return explanations.get(anomaly_type, f"⚠️ Anomaly: {details}")

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'my-super-secret-jwt-key-12345')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)



jwt = JWTManager(app)
CORS(app)

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', 5432)),
    'database': os.getenv('DB_NAME', 'signup'),
    'user': os.getenv('DB_USER', 'postgres'),
    'password': os.getenv('DB_PASSWORD', 'root')
}

def get_db_connection():
    try:
        connection = psycopg2.connect(**DB_CONFIG)
        return connection
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

def create_tables():
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    hashed_password VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            print(f"Error creating tables: {e}")
            return False
    return False

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def store_user(email, hashed_password):
    conn = get_db_connection()
    if conn:
        try:
            # First check if user already exists
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE email = %s;", (email,))
            existing_user = cursor.fetchone()
            
            if existing_user:
                cursor.close()
                conn.close()
                return None  # User already exists
            
            # If user doesn't exist, create new user
            cursor.execute(
                "INSERT INTO users (email, hashed_password) VALUES (%s, %s) RETURNING id;",
                (email, hashed_password.decode('utf-8'))
            )
            user_id = cursor.fetchone()[0]
            conn.commit()
            cursor.close()
            conn.close()
            return user_id
        except Exception as e:
            print(f"Error storing user: {e}")
            return None
    return None

def authenticate_user(email, password):
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, email, hashed_password FROM users WHERE email = %s;", (email,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            if user and verify_password(password, user[2]):
                return {'id': user[0], 'email': user[1], 'authenticated': True}
            return None
        except Exception as e:
            print(f"Authentication error: {e}")
            return None
    return None

def create_user_tokens(user_id, email):
    try:
        access_token = create_access_token(identity=user_id, additional_claims={'email': email})
        refresh_token = create_refresh_token(identity=user_id, additional_claims={'email': email})
        return {'access_token': access_token, 'refresh_token': refresh_token}
    except Exception as e:
        print(f"Token creation error: {e}")
        return None

def get_user_by_id(user_id):
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, email, created_at FROM users WHERE id = %s;", (user_id,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            if user:
                return {'id': user[0], 'email': user[1], 'created_at': user[2]}
            return None
        except Exception as e:
            print(f"Error getting user: {e}")
            return None
    return None

def parse_csv_content(content):
    """Parse CSV content and return all fields as JSON array"""
    try:
        lines = content.strip().split('\n')
        if len(lines) < 2:  # Need at least header + 1 data row
            return None, "CSV must have at least a header row and one data row"
        
        # Parse CSV using csv module
        csv_reader = csv.DictReader(lines)
        
        # Get available fields from the CSV
        available_fields = csv_reader.fieldnames or []
        print(f"Available fields in CSV: {available_fields}")
        
        # Parse all rows and keep all fields
        log_entries = []
        total_rows = 0
        
        for row in csv_reader:
            total_rows += 1
            # Keep all fields from the CSV
            log_entry = {}
            for field in available_fields:
                log_entry[field] = row[field] if row[field] else ""
            log_entries.append(log_entry)
        
        # Perform simplified anomaly detection
        log_entries_with_anomalies = detect_anomalies(log_entries)
        
        # Count anomalies
        total_records = len(log_entries_with_anomalies)
        anomaly_count = len([e for e in log_entries_with_anomalies if e.get('is_anomaly')])
        anomalies = [e for e in log_entries_with_anomalies if e.get('is_anomaly')]
        
        # Calculate anomaly percentage for better risk assessment
        anomaly_percentage = (anomaly_count / total_records) * 100 if total_records > 0 else 0
        
        # Two-tier AI integration with fallback
        soc_report = None
        
        # Tier 1: Try Gemini 2.0 Flash AI (Primary)
        try:
            if AI_AVAILABLE and ai_generator:
                print("Attempting Gemini 2.0 Flash AI generation...")
                ai_report = ai_generator.generate_soc_report(log_entries_with_anomalies, anomalies)
                if ai_report and ai_report.get('soc_analysis'):
                    soc_report = ai_report
                    print("✅ Gemini 2.0 Flash AI generation successful")
                else:
                    raise Exception("AI returned invalid data")
            else:
                raise Exception("AI not available")
        except Exception as e:
            print(f"❌ Gemini 2.0 Flash AI failed: {e}")
            
            # Tier 2: Use template fallback (Always works)
            print("Using template fallback...")
            soc_report = {
                'executive_summary': f"📊 Log Analysis Complete: {total_records} entries, {anomaly_count} anomalies ({anomaly_percentage:.1f}%)",
                'total_records': total_records,
                'total_anomalies': anomaly_count,
                'anomaly_percentage': round(anomaly_percentage, 2),
                'risk_assessment': 'LOW' if anomaly_count == 0 else 'MEDIUM' if anomaly_count < 5 else 'HIGH',
                'risk_description': 'Template-based analysis completed',
                'recommended_actions': ['Review anomalies for investigation'] if anomaly_count > 0 else ['No action required - all clear'],
                'timeline_events': [],
                'key_learnings': ['Template analysis completed']
            }
            print("✅ Template fallback successful")
        
        return {
            'file_type': 'csv',
            'total_rows': total_rows,
            'available_fields': available_fields,
            'log_entries': log_entries_with_anomalies,
            'sample_entries': log_entries_with_anomalies[:20] if log_entries_with_anomalies else [],  # Show first 20 entries as sample
            'soc_report': soc_report  # Include SOC report
        }, None
        
    except Exception as e:
        print(f"CSV parsing error: {e}")
        return None, f"CSV parsing failed: {str(e)}"


def detect_anomalies(log_entries):
    """Simplified anomaly detection focusing on key security indicators"""
    try:
        if not log_entries:
            return log_entries
        
        # Simple counters
        ip_counts = {}
        user_counts = {}
        
        # First pass: count requests per entity
        for entry in log_entries:
            if 'src_ip' in entry and entry['src_ip']:
                ip_counts[entry['src_ip']] = ip_counts.get(entry['src_ip'], 0) + 1
            
            if 'user' in entry and entry['user']:
                user_counts[entry['user']] = user_counts.get(entry['user'], 0) + 1
        
        # Calculate simple averages
        total_entries = len(log_entries)
        avg_per_ip = total_entries / max(len(ip_counts), 1)
        avg_per_user = total_entries / max(len(user_counts), 1)
        
        # Second pass: detect anomalies
        for entry in log_entries:
            anomalies = []
            
            # High volume detection (check both IP and user, but only flag once)
            if 'src_ip' in entry and entry['src_ip']:
                ip_count = ip_counts.get(entry['src_ip'], 0)
                user_count = user_counts.get(entry['user'], 0) if 'user' in entry and entry['user'] else 0
                
                # Use the higher count to determine if it's high volume
                max_count = max(ip_count, user_count)
                if max_count > avg_per_ip * 3.0:  # Increased threshold - less sensitive to normal traffic spikes
                    anomalies.append(f"🚨 High volume: {max_count} requests")
            
            # Security threat detection
            if 'threat_count' in entry and entry['threat_count']:
                try:
                    threat_count = float(entry['threat_count'])
                    if threat_count > 0:
                        anomalies.append(f"🛡️ Security threat: {threat_count} threats detected")
                except (ValueError, TypeError):
                    pass
            
            if 'malware_count' in entry and entry['malware_count']:
                try:
                    malware_count = float(entry['malware_count'])
                    if malware_count > 0:
                        anomalies.append(f"🛡️ Malware detected: {malware_count} instances")
                except (ValueError, TypeError):
                    pass
            
            # HTTP error detection
            if 'http_status' in entry and entry['http_status']:
                status = entry['http_status']
                if status in ['401', '403', '500']:
                    anomalies.append(f"❌ HTTP error: Status {status}")
            
            # Suspicious URL detection
            if 'url' in entry and entry['url']:
                url = entry['url'].lower()
                suspicious_patterns = ['admin', 'login', 'config', 'backup', 'php', 'shell']
                for pattern in suspicious_patterns:
                    if pattern in url:
                        anomalies.append(f"⚠️ Suspicious URL: {pattern} detected in {entry['url']}")
                        break
            
            # Set anomaly flags and calculate real confidence
            if anomalies:
                entry['is_anomaly'] = True
                entry['anomaly_reasons'] = anomalies
                # Calculate real confidence based on number of reasons and severity
                base_confidence = min(0.95, 0.6 + (len(anomalies) * 0.1))
                entry['anomaly_confidence'] = round(base_confidence, 2)
            else:
                entry['is_anomaly'] = False
                entry['anomaly_reasons'] = []
                entry['anomaly_confidence'] = 0.0
        
        # NEW: ML-based anomaly detection with Isolation Forest
        try:
            from sklearn.ensemble import IsolationForest
            import numpy as np
            
            # Prepare features for ML
            ml_features = []
            for entry in log_entries:
                # Extract numeric features for ML
                bytes_sent = float(entry.get('bytes_sent', 0) or 0)
                bytes_received = float(entry.get('bytes_received', 0) or 0)
                threat_count = float(entry.get('threat_count', 0) or 0)
                malware_count = float(entry.get('malware_count', 0) or 0)
                ssl_validity = float(entry.get('ssl_cert_validity_days', 365) or 365)
                
                # Convert timestamp to hour of day (0-23) for time-based patterns
                timestamp = str(entry.get('timestamp', ''))
                hour = 9  # Default to 9 AM if parsing fails
                if ' ' in timestamp:
                    try:
                        time_part = timestamp.split(' ')[1]
                        hour = int(time_part.split(':')[0])
                    except:
                        pass
                
                features = [bytes_sent, bytes_received, threat_count, malware_count, ssl_validity, hour]
                ml_features.append(features)
            
            # Train Isolation Forest (unsupervised - no labels needed)
            iso_forest = IsolationForest(contamination=0.15, random_state=42, n_estimators=100)
            anomaly_scores = iso_forest.fit_predict(ml_features)
            
            # Combine ML results with rule-based results
            ml_anomalies_found = 0
            for i, entry in enumerate(log_entries):
                ml_score = anomaly_scores[i]
                
                # ML detected anomaly (-1 = anomaly, 1 = normal)
                if ml_score == -1:
                    ml_anomalies_found += 1
                    
                    # If ML detects anomaly but rules didn't, add ML reason
                    if not entry.get('is_anomaly'):
                        entry['is_anomaly'] = True
                        entry['anomaly_reasons'] = []
                        entry['anomaly_confidence'] = 0.0
                    
                    # Add ML-based reason with clear ML indicator
                    ml_reason = "🤖 ML Detected: Unusual activity pattern"
                    entry['anomaly_reasons'].append(ml_reason)
                    
                    # Set ML confidence (ML detection is highly reliable)
                    if entry.get('anomaly_confidence', 0) > 0:
                        # If rules also detected it, boost confidence
                        entry['anomaly_confidence'] = min(0.98, entry['anomaly_confidence'] + 0.15)
                    else:
                        # Pure ML detection
                        entry['anomaly_confidence'] = 0.85
            
            # ML detection completed
                    
        except ImportError:
            # Fallback if sklearn not available
            pass
        except Exception as ml_error:
            # Continue with rule-based detection only
            pass
        
        # Enhanced reporting
        total_anomalies = sum(1 for entry in log_entries if entry['is_anomaly'])
        # Enhanced anomaly detection completed
        

        
        return log_entries
        
    except Exception as e:
        # Return original entries with default values
        for entry in log_entries:
            entry['is_anomaly'] = False
            entry['anomaly_reasons'] = []
        return log_entries

def generate_soc_report(log_entries):
    """Generate enhanced AI-powered SOC summary for findings"""
    try:

        
        # Basic counts
        total_records = len(log_entries)
        
        # Debug: Check what fields are available
        # Try to find anomalies using multiple methods
        anomaly_records = []
        for entry in log_entries:
            # Method 1: Check is_anomaly field
            if entry.get('is_anomaly'):
                anomaly_records.append(entry)
            # Method 2: Check if anomaly_reasons exist
            elif entry.get('anomaly_reasons') and len(entry.get('anomaly_reasons', [])) > 0:
                anomaly_records.append(entry)
            # Method 3: Check if it's marked as suspicious in any way
            elif entry.get('action') == 'blocked' or entry.get('http_status', 200) >= 400:
                anomaly_records.append(entry)
        
        total_anomalies = len(anomaly_records)
        
        # Anomaly detection completed
        
        # Try enhanced AI generation first
        if ai_generator and AI_AVAILABLE:
            try:
                soc_report = ai_generator.generate_soc_report(log_entries, anomaly_records)
                return soc_report
                
            except Exception as e:
                return ai_generator.generate_fallback_report(log_entries, anomaly_records)
        else:
            # Use fallback logic
            return generate_fallback_soc_report(log_entries, anomaly_records)
        
    except Exception as e:
        return generate_error_fallback(log_entries, e)

def generate_fallback_soc_report(log_entries, anomaly_records):
    """Generate fallback SOC report when AI is not available"""
    try:
        total_records = len(log_entries)
        total_anomalies = len(anomaly_records)
        
        # Calculate anomaly percentage for better risk assessment
        anomaly_percentage = (total_anomalies / total_records) * 100 if total_records > 0 else 0
        
        # Simple summary with proper threat level calculation
        if total_anomalies == 0:
            summary = f"✅ SECURITY CLEAR: {total_records} log entries analyzed. No anomalies detected."
            risk_level = 'SECURE'
        else:
            summary = f"⚠️ SECURITY ALERT: {total_records} log entries analyzed. {total_anomalies} anomalies ({anomaly_percentage:.1f}%) found."
            # Enhanced percentage-based threat level calculation
            if anomaly_percentage <= 2:  # 0-2%
                risk_level = 'VERY_LOW'
            elif anomaly_percentage <= 5:  # 2-5%
                risk_level = 'LOW'
            elif anomaly_percentage <= 10:  # 5-10%
                risk_level = 'MEDIUM'
            elif anomaly_percentage <= 20:  # 10-20%
                risk_level = 'HIGH'
            else:  # >20%
                risk_level = 'CRITICAL'
        
        # Create fallback SOC summary
        soc_summary = {
            'soc_analysis': {
                'executive_summary': summary,
                'key_findings': [],
                'timeline_analysis': {'events': [], 'narrative': 'Timeline analysis not available'},
                'soc_recommendations': {
                    'immediate': [{'title': 'Review Anomalies', 'description': 'Review all detected anomalies', 'action_steps': ['Document findings']}],
                    'short_term': [],
                    'long_term': []
                }
            },
            'anomaly_analysis': {
                'total_anomalies': total_anomalies,
                'anomaly_types': {},
                'ml_confidence': 0.0,
                'detection_method': 'Fallback Template System'
            },
            'total_records': total_records,
            'total_anomalies': total_anomalies,
            'anomaly_percentage': round(anomaly_percentage, 2),
            'threat_level': risk_level,
            'generated_at': datetime.now().isoformat(),
            'analysis_method': 'Fallback Template System'
        }
        
        return soc_summary
        
    except Exception as e:
        return generate_error_fallback(log_entries, e)

def generate_error_fallback(log_entries, error):
    """Generate error fallback when all else fails"""
    return {
        'soc_analysis': {
            'executive_summary': f'Error generating SOC report: {str(error)}',
            'key_findings': [],
            'timeline_analysis': {'events': [], 'narrative': 'Error in timeline generation'},
            'soc_recommendations': {'immediate': [], 'short_term': [], 'long_term': []}
        },
        'anomaly_analysis': {
            'total_anomalies': 0,
            'anomaly_types': {},
            'ml_confidence': 0.0,
            'detection_method': 'Error'
        },
        'total_records': len(log_entries),
        'total_anomalies': 0,
        'threat_level': 'ERROR',
        'generated_at': datetime.now().isoformat(),
        'analysis_method': 'Error Fallback'
    }

@app.route('/')
def home():
    return {'message': 'LogCheckAI Backend is working!'}



@app.route('/generate-soc-report', methods=['POST'])
@jwt_required()
def generate_soc_report_endpoint():
    """Generate SOC report for uploaded log data"""
    try:
        current_user_id = get_jwt_identity()
        user = get_user_by_id(current_user_id)
        
        if not user:
            return {'message': 'User not found'}, 404
        
        data = request.get_json()
        log_entries = data.get('log_entries', [])
        
        if not log_entries:
            return {'message': 'No log entries provided'}, 400
        
        # Generate SOC Report

        soc_report = generate_soc_report(log_entries)
        
        return {
            'message': 'SOC Report generated successfully',
            'user_email': user['email'],
            'soc_report': soc_report
        }, 200
        
    except Exception as e:
        return {'error': f'SOC report generation failed: {str(e)}'}, 500



@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        if not email or not password:
            return {'message': 'Email and password required'}, 400
        
        # Check if user already exists
        conn = get_db_connection()
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM users WHERE email = %s;", (email,))
                existing_user = cursor.fetchone()
                cursor.close()
                conn.close()
                
                if existing_user:
                    return {
                        'message': 'User already exists with this email address. Please login instead.',
                        'user_exists': True
                    }, 409  # Conflict status code
            except Exception as e:
                print(f"Error checking existing user: {e}")
        
        hashed_password = hash_password(password)
        user_id = store_user(email, hashed_password)
        if user_id:
            return {
                'message': 'User registered successfully',
                'user': {'id': user_id, 'email': email}
            }, 201
        return {'message': 'Registration failed'}, 400
    except Exception as e:
        print(f"Signup error: {e}")
        return {'message': 'Internal server error'}, 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        if not email or not password:
            return {'message': 'Email and password required'}, 400
        
        # Check if user exists first
        conn = get_db_connection()
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT id, email, hashed_password FROM users WHERE email = %s;", (email,))
                user = cursor.fetchone()
                cursor.close()
                conn.close()
                
                if not user:
                    return {
                        'message': 'Incorrect email or password'
                    }, 401
                
                # User exists, now verify password
                if verify_password(password, user[2]):
                    # Password is correct, create tokens
                    tokens = create_user_tokens(user[0], user[1])
                    if tokens:
                        return {
                            'message': 'Login successful',
                            'user': {'id': user[0], 'email': user[1]},
                            'access_token': tokens['access_token'],
                            'refresh_token': tokens['refresh_token']
                        }, 200
                    else:
                        return {'message': 'Login failed - token creation error'}, 500
                else:
                    # Password is incorrect
                    return {
                        'message': 'Incorrect email or password'
                    }, 401
                    
            except Exception as e:
                print(f"Login error: {e}")
                return {'message': 'Internal server error during login'}, 500
        else:
            return {'message': 'Database connection failed'}, 500
            
    except Exception as e:
        print(f"Login error: {e}")
        return {'message': 'Internal server error'}, 500

@app.route('/upload-simple', methods=['POST'])
def upload_simple():
    try:
        if 'file' not in request.files:
            return {'message': 'No file provided'}, 400
        
        file = request.files['file']
        if file.filename == '':
            return {'message': 'No file selected'}, 400
        
        try:
            content = file.read().decode('utf-8')
            
            # Check if it's a CSV file (txt/log files with CSV content)
            if ',' in content.split('\n')[0]:
                # Parse as CSV and return clean array format
                parsed_data, error = parse_csv_content(content)
                if error:
                    return {'message': error}, 400
                
                return {
                    'message': 'CSV file parsed successfully!',
                    'filename': file.filename,
                    'file_type': 'csv',
                    'total_rows': parsed_data['total_rows'],
                    'available_fields': parsed_data['available_fields'],
                    'log_entries': parsed_data['log_entries'],  # Clean array of log entries
                    'soc_report': parsed_data.get('soc_report')  # Include SOC report!
                }, 200
            else:
                # Regular text file
                lines = content.split('\n')
                return {
                    'message': 'Text file processed successfully!',
                    'filename': file.filename,
                    'file_type': 'text',
                    'total_lines': len(lines),
                    'content': content
                }, 200
            
        except UnicodeDecodeError:
            file.seek(0)
            content = file.read().decode('utf-8', errors='ignore')
            lines = content.split('\n')
            
            return {
                'message': 'File processed (with encoding fixes)!',
                'filename': file.filename,
                'file_type': 'text',
                'total_lines': len(lines),
                'content': content
            }, 200
        
    except Exception as e:
        print(f"Upload error: {e}")
        return {
            'message': 'File processing failed',
            'error': str(e)
        }, 500

@app.route('/process', methods=['POST'])
@jwt_required()
def process_log():
    try:
        current_user_id = get_jwt_identity()
        user = get_user_by_id(current_user_id)
        
        if not user:
            return {'message': 'User not found'}, 404
        
        if 'file' not in request.files:
            return {'message': 'No file provided'}, 400
        
        file = request.files['file']
        if file.filename == '':
            return {'message': 'No file selected'}, 400
        
        try:
            file.seek(0)
            content = file.read().decode('utf-8')
            
            # Check if it's a CSV file
            if file.filename.endswith('.csv') or ',' in content.split('\n')[0]:
                # Parse as CSV and return all fields
                parsed_data, error = parse_csv_content(content)
                if error:
                    return {'message': error}, 400
                
                json_data = {
                    'file_type': 'csv',
                    'filename': file.filename,
                    'content': content,
                    'total_lines': len(content.split('\n')),
                    'file_size_bytes': len(content),
                    'file_size_kb': round(len(content) / 1024, 2),
                    'csv_analysis': parsed_data
                }
                
                return {
                    'message': 'CSV file parsed successfully!',
                    'filename': file.filename,
                    'user_email': user['email'],
                    'status': 'parsed_csv',
                    'json_data': json_data,
                    'log_entries': parsed_data['log_entries'] if parsed_data else [],
                    'soc_report': parsed_data.get('soc_report')  # Include SOC report!
                }, 200
            else:
                # Regular text file
                json_data = {
                    'file_type': 'text',
                    'filename': file.filename,
                    'content': content,
                    'total_lines': len(content.split('\n')),
                    'file_size_bytes': len(content),
                    'file_size_kb': round(len(content) / 1024, 2)
                }
                
                return {
                    'message': 'File content displayed successfully!',
                    'filename': file.filename,
                    'user_email': user['email'],
                    'status': 'displayed',
                    'json_data': json_data
                }, 200
            
        except UnicodeDecodeError:
            file.seek(0)
            content = file.read().decode('utf-8', errors='ignore')
            lines = content.split('\n')
            json_data = {
                'file_type': 'text',
                'filename': file.filename,
                'content': content,
                'total_lines': len(lines),
                'note': 'File decoded with encoding errors ignored'
            }
            
            return {
                'message': 'File content displayed (with encoding fixes)!',
                'filename': file.filename,
                'user_email': user['email'],
                'status': 'displayed_with_warnings',
                'json_data': json_data
            }, 200
        
    except Exception as e:
        print(f"Process error: {e}")
        return {
            'message': 'File processing failed',
            'error': str(e)
        }, 500

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    try:
        current_user_id = get_jwt_identity()
        user = get_user_by_id(current_user_id)
        if user:
            new_access_token = create_access_token(identity=current_user_id, additional_claims={'email': user['email']})
            return {'access_token': new_access_token}, 200
        return {'message': 'User not found'}, 404
    except Exception as e:
        print(f"Refresh error: {e}")
        return {'message': 'Token refresh failed'}, 500

if __name__ == '__main__':
    print("Starting LogCheckAI Backend...")
    if create_tables():
        print("Starting web server...")
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        print("Failed to create tables. Check database connection.")
