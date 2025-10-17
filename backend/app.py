from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from dotenv import load_dotenv
import psycopg2
import bcrypt
import os
import csv
import json
from datetime import timedelta, datetime
import re
from collections import defaultdict, Counter

# Import enhanced AI SOC generator
try:
    from enhanced_ai_soc import EnhancedAISOCGenerator
    AI_AVAILABLE = True
    ai_generator = EnhancedAISOCGenerator()
except ImportError as e:
    AI_AVAILABLE = False
    ai_generator = None

load_dotenv()

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
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE email = %s;", (email,))
            existing_user = cursor.fetchone()
            
            if existing_user:
                cursor.close()
                conn.close()
                return None
            
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
        if len(lines) < 2:
            return None, "CSV must have at least a header row and one data row"
        
        csv_reader = csv.DictReader(lines)
        available_fields = csv_reader.fieldnames or []
        print(f"Available fields in CSV: {available_fields}")
        
        log_entries = []
        total_rows = 0
        
        for row in csv_reader:
            total_rows += 1
            log_entry = {}
            for field in available_fields:
                log_entry[field] = row[field] if row[field] else ""
            log_entries.append(log_entry)
        
        # Perform anomaly detection
        log_entries_with_anomalies = detect_anomalies(log_entries)
        
        # Count anomalies
        total_records = len(log_entries_with_anomalies)
        anomaly_count = len([e for e in log_entries_with_anomalies if e.get('is_anomaly')])
        anomalies = [e for e in log_entries_with_anomalies if e.get('is_anomaly')]
        
        # Calculate threat level
        if anomaly_count == 0:
            threat_level = 'SECURE'
        elif anomaly_count <= total_records * 0.25:
            threat_level = 'LOW'
        elif anomaly_count <= total_records * 0.50:
            threat_level = 'MEDIUM'
        else:
            threat_level = 'HIGH'
        
        # Generate SOC report using enhanced AI
        soc_report = None
        if AI_AVAILABLE and ai_generator:
            try:
                soc_report = ai_generator.generate_soc_report(log_entries_with_anomalies, anomalies, None, threat_level)
                print("✅ AI SOC report generated successfully")
            except Exception as e:
                print(f"❌ AI generation failed: {e}")
                soc_report = None
        
        return {
            'file_type': 'csv',
            'total_rows': total_rows,
            'available_fields': available_fields,
            'log_entries': log_entries_with_anomalies,
            'sample_entries': log_entries_with_anomalies[:20] if log_entries_with_anomalies else [],
            'soc_report': soc_report,
            'total_entries': total_records,
            'total_anomalies': anomaly_count,
            'threat_level': threat_level,
            'anomalies': anomalies
        }, None
        
    except Exception as e:
        print(f"CSV parsing error: {e}")
        return None, f"CSV parsing failed: {str(e)}"

def detect_anomalies(log_entries):
    """Enhanced anomaly detection with ML support"""
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
        
        # Calculate averages
        total_entries = len(log_entries)
        avg_per_ip = total_entries / max(len(ip_counts), 1)
        avg_per_user = total_entries / max(len(user_counts), 1)
        
        # Second pass: detect anomalies
        for entry in log_entries:
            anomalies = []
            

            # High volume detection
            if 'src_ip' in entry and entry['src_ip']:
                ip_count = ip_counts.get(entry['src_ip'], 0)
                user_count = user_counts.get(entry['user'], 0) if 'user' in entry and entry['user'] else 0
                max_count = max(ip_count, user_count)
                if max_count > avg_per_ip * 3.0:
                    anomalies.append(f"High volume: {max_count} requests;")
            
            # Security threat detection
            if 'threat_count' in entry and entry['threat_count']:
                try:
                    threat_count = float(entry['threat_count'])
                    if threat_count > 0:
                        anomalies.append(f" Security threat: {threat_count} threats detected;")
                except (ValueError, TypeError):
                    pass
            
            if 'malware_count' in entry and entry['malware_count']:
                try:
                    malware_count = float(entry['malware_count'])
                    if malware_count > 0:
                        anomalies.append(f" Malware detected: {malware_count} instances;")
                except (ValueError, TypeError):
                    pass
            
            # HTTP error detection
            if 'http_status' in entry and entry['http_status']:
                status = entry['http_status']
                if status in ['401', '403', '500']:
                    anomalies.append(f" HTTP error: Status {status};")
            
            # Suspicious URL detection
            if 'url' in entry and entry['url']:
                url = entry['url'].lower()
                suspicious_patterns = ['admin', 'login', 'config', 'backup', 'php', 'shell']
                for pattern in suspicious_patterns:
                    if pattern in url:
                        anomalies.append(f" Suspicious URL pattern: {pattern};")
                        break
            
            
            # Set anomaly status
            if anomalies:
                entry['is_anomaly'] = True
                entry['anomaly_reasons'] = anomalies
                entry['anomaly_confidence'] = min(0.95, 0.7 + (len(anomalies) * 0.1))
            else:
                entry['is_anomaly'] = False
                entry['anomaly_reasons'] = []
                entry['anomaly_confidence'] = 0.0
        

        
        # ML-based anomaly detection with Isolation Forest
        try:
            from sklearn.ensemble import IsolationForest
            import numpy as np
            
            # Prepare features for ML
            ml_features = []
            for entry in log_entries:
                bytes_sent = float(entry.get('bytes_sent', 0) or 0)
                bytes_received = float(entry.get('bytes_received', 0) or 0)
                threat_count = float(entry.get('threat_count', 0) or 0)
                malware_count = float(entry.get('malware_count', 0) or 0)
                ssl_validity = float(entry.get('ssl_cert_validity_days', 365) or 365)
                
                # Convert timestamp to hour of day
                timestamp = str(entry.get('timestamp', ''))
                hour = 9
                if ' ' in timestamp:
                    try:
                        time_part = timestamp.split(' ')[1]
                        hour = int(time_part.split(':')[0])
                    except:
                        pass
                
                features = [bytes_sent, bytes_received, threat_count, malware_count, ssl_validity, hour]
                ml_features.append(features)
            
            # Train Isolation Forest
            iso_forest = IsolationForest(contamination=0.15, random_state=42, n_estimators=100)
            anomaly_scores = iso_forest.fit_predict(ml_features)
            
            # Combine ML results with rule-based results
            for i, entry in enumerate(log_entries):
                ml_score = anomaly_scores[i]
                
                if ml_score == -1:  # ML detected anomaly
                    if not entry.get('is_anomaly'):
                        entry['is_anomaly'] = True
                        entry['anomaly_reasons'] = []
                        entry['anomaly_confidence'] = 0.0
                    
                    ml_reason = "ML Detected: Unusual activity pattern"
                    entry['anomaly_reasons'].append(ml_reason)
                    
                    if entry.get('anomaly_confidence', 0) > 0:
                        entry['anomaly_confidence'] = min(0.98, entry['anomaly_confidence'] + 0.15)
                    else:
                        entry['anomaly_confidence'] = 0.85
                    
        except ImportError:
            pass
        except Exception as ml_error:
            pass
        
        return log_entries
        
    except Exception as e:
        # Return original entries with default values
        for entry in log_entries:
            entry['is_anomaly'] = False
            entry['anomaly_reasons'] = []
        return log_entries

# ===== ROUTES =====

@app.route('/filter', methods=['POST'])
def filter():
    data=request.get_json()
    log_entries=data.get('log_entries')
    fromTimestamp=data.get('fromTimestamp')
    toTimestamp=data.get('toTimestamp')

    fromTime=datetime.strptime(fromTimestamp, "%Y-%m-%d %H:%M:%S")
    toTime=datetime.strptime(toTimestamp, "%Y-%m-%d %H:%M:%S")

    res=[]

    for entry in log_entries:
        timestamp=entry['timestamp']
        dt=datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

        if dt>=fromTime and dt<toTime:
            res.append(entry)
    
    return jsonify({"result":res})



@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'message': 'Email and password are required'}), 400
        
        if len(password) < 6:
            return jsonify({'message': 'Password must be at least 6 characters'}), 400
        
        hashed_password = hash_password(password)
        user_id = store_user(email, hashed_password)
        
        if user_id:
            return jsonify({'message': 'User registered successfully'}), 201
        else:
            return jsonify({'message': 'User already exists'}), 409
            
    except Exception as e:
        return jsonify({'message': f'Registration failed: {str(e)}'}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'message': 'Email and password are required'}), 400
        
        user = authenticate_user(email, password)
        
        if user and user['authenticated']:
            tokens = create_user_tokens(user['id'], user['email'])
            if tokens:
                return jsonify({
                    'message': 'Login successful',
                    'access_token': tokens['access_token'],
                    'refresh_token': tokens['refresh_token'],
                    'user': {'id': user['id'], 'email': user['email']}
                }), 200
            else:
                return jsonify({'message': 'Token creation failed'}), 500
        else:
            return jsonify({'message': 'Invalid credentials'}), 401
            
    except Exception as e:
        return jsonify({'message': f'Login failed: {str(e)}'}), 500

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    try:
        current_user_id = get_jwt_identity()
        user = get_user_by_id(current_user_id)
        
        if user:
            tokens = create_user_tokens(user['id'], user['email'])
            if tokens:
                return jsonify({
                    'access_token': tokens['access_token'],
                    'expires_in': 3600
                }), 200
            else:
                return jsonify({'message': 'Token refresh failed'}), 500
        else:
            return jsonify({'message': 'User not found'}), 404
            
    except Exception as e:
        return jsonify({'message': f'Refresh failed: {str(e)}'}), 500



@app.route('/upload-simple', methods=['POST'])
def upload_simple():
    try:
        if 'file' not in request.files:
            return jsonify({'message': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'message': 'No file selected'}), 400
        
        if not file.filename.endswith(('.txt', '.log')):
            return jsonify({'message': 'Only .txt and .log files are allowed'}), 400
        
        # Read file content
        content = file.read().decode('utf-8')
        
        # Parse content based on file type
        result, error = parse_csv_content(content)
        
        if error:
            return jsonify({'message': error}), 400
        
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({'message': f'Upload failed: {str(e)}'}), 500

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    try:
        current_user_id = get_jwt_identity()
        user = get_user_by_id(current_user_id)
        
        if user:
            return jsonify({
                'message': 'Access granted',
                'user': user
            }), 200
        else:
            return jsonify({'message': 'User not found'}), 404
            
    except Exception as e:
        return jsonify({'message': f'Protected route error: {str(e)}'}), 500

if __name__ == '__main__':
    create_tables()
    app.run(debug=True, host='0.0.0.0', port=5000)