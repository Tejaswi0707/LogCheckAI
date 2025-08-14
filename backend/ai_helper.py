import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def generate_fallback_summary(log_entries, anomalies, threat_level):
    """
    Fallback summary when AI fails
    Returns a basic but professional summary
    """
    total_entries = len(log_entries)
    total_anomalies = len(anomalies)
    anomaly_percentage = (total_anomalies / total_entries * 100) if total_entries > 0 else 0
    
    if total_anomalies == 0:
        return f"Security analysis of {total_entries} log entries reveals no anomalies detected. The system appears to be operating within normal security parameters with a {threat_level} threat level."
    elif anomaly_percentage <= 25:
        return f"Security analysis of {total_entries} log entries identified {total_anomalies} anomalies ({anomaly_percentage:.1f}% rate). The {threat_level} threat level indicates minor security concerns requiring routine monitoring and investigation."
    elif anomaly_percentage <= 50:
        return f"Security analysis of {total_entries} log entries detected {total_anomalies} anomalies ({anomaly_percentage:.1f}% rate). The {threat_level} threat level suggests moderate security threats requiring immediate attention from the SOC team."
    else:
        return f"Security analysis of {total_entries} log entries revealed {total_anomalies} anomalies ({anomaly_percentage:.1f}% rate). The {threat_level} threat level indicates critical security incidents requiring immediate emergency response and containment measures."

def generate_gemini_summary(log_entries, anomalies, threat_level):
    """Generate AI-powered log analysis summary using Gemini"""
    try:
        # Check if Gemini is enabled
        gemini_enabled = True #os.getenv('GEMINI_ENABLED', 'false').lower() == 'true'
        if not gemini_enabled:
            return generate_fallback_summary(log_entries, anomalies, threat_level)
        
        api_key = os.getenv('GEMINI_API_KEY')
        # Validate API key format and availability
        if not api_key or len(api_key.strip()) < 10 or api_key == 'your_api_key' or 'your_api_key' in api_key:
            # Skip API call entirely if key is invalid/missing/placeholder
            return generate_fallback_summary(log_entries, anomalies, threat_level)
        
        # Import Gemini (only when needed)
        #from google import generativeai as genai
        import google.generativeai as genai
        
        # Configure Gemini
        genai.configure(api_key=api_key)
        
        # Create prompt for log analysis
        total_entries = len(log_entries)
        total_anomalies = len(anomalies)
        anomaly_percentage = (total_anomalies / total_entries * 100) if total_entries > 0 else 0
        
        prompt = f"""Analyze this security log data and provide the most important information for SOC analysts in 10-15 lines.

Log Analysis: {total_entries} entries, {total_anomalies} anomalies ({anomaly_percentage:.1f}% rate)
Threat Level: {threat_level}

Focus on providing the most critical information a SOC analyst needs:
Current threat situation and severity assessment
Key indicators and patterns that require immediate attention
Most important learnings and insights from the analysis
Critical actions the SOC analyst should take first
What to investigate and prioritize
Any unusual or concerning patterns detected

Present this information in a clear, human-consumable format that helps SOC analysts make quick, informed decisions. Use natural language and focus on actionable intelligence.

IMPORTANT: Do not use any bullet points, stars, or special formatting. Do not mention the threat level at the beginning of your response."""

        # Generate response using Gemini
        model = genai.GenerativeModel('gemini-2.0-flash')
        response = model.generate_content(prompt)
        print(response)
        if response and response.text:
            ai_summary = response.text.strip()
            
            # Check if response is meaningful
            if ai_summary and len(ai_summary) > 20:
                return f"AI Analysis: {ai_summary}"
            else:
                print('failed to get the response from gemini')
                print(response)
                return generate_fallback_summary(log_entries, anomalies, threat_level)
        else:
            # API failed, use fallback without logging errors
            print("failed here")
            return generate_fallback_summary(log_entries, anomalies, threat_level)
            
    except Exception as e:
        # Any error, use fallback silently
        print(e)
        return generate_fallback_summary(log_entries, anomalies, threat_level)