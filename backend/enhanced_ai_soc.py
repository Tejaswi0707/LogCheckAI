import os
from dotenv import load_dotenv
import google.generativeai as genai
from datetime import datetime
import random

# Load environment variables
load_dotenv()

class EnhancedAISOCGenerator:
    def __init__(self):
        self.gemini_available = False
        self.model = None
        
        # Initialize Gemini if available
        api_key = os.getenv('GEMINI_API_KEY')
        if api_key:
            try:
                genai.configure(api_key=api_key)
                self.gemini_available = True
                self.model = genai.GenerativeModel('gemini-2.0-flash')
                print("✅ Gemini AI initialized successfully")
            except Exception as e:
                print(f"❌ Gemini AI initialization failed: {e}")
                self.gemini_available = False
        
        # Professional SOC templates
        self.soc_templates = {
            'AI Analysis': [
                "Security analysis of {total_entries} log entries identified {total_anomalies} anomalies ({anomaly_percentage:.1f}% rate). The {threat_level} threat level indicates {severity_assessment} requiring {action_required}.",
                "Based on analysis of {total_entries} security logs, {total_anomalies} anomalous activities were detected ({anomaly_percentage:.1f}% anomaly rate). Current threat assessment: {threat_level} - {business_impact}.",
                "SOC analysis of {total_entries} log entries reveals {total_anomalies} security anomalies ({anomaly_percentage:.1f}% detection rate). Threat level: {threat_level}. {recommendation}."
            ]
        }
    
    def generate_soc_report(self, log_entries, anomalies, time_range=None, threat_level=None, filename="unknown_file"):
        """Generate comprehensive SOC report with AI enhancement"""
        try:
            # Try AI generation first
            ai_summary = self._try_gemini_ai(log_entries, anomalies, threat_level)
            if ai_summary and len(ai_summary) > 30:
                return ai_summary
        except Exception as e:
            print(f"AI generation failed, using fallback: {e}")
        
        # Fallback to professional templates
        return self._generate_template_summary(log_entries, anomalies, threat_level)
    
    def _try_gemini_ai(self, log_entries, anomalies, threat_level):
        """Try to generate AI response using Gemini, fallback to templates if it fails"""
        if not self.gemini_available or not self.model:
            return None
        
        try:
            # Create sample anomalies for context
            sample_anomalies = []
            for i, anomaly in enumerate(anomalies[:3]):
                sample_anomalies.append({
                    'index': i + 1,
                    'timestamp': anomaly.get('timestamp', 'Unknown'),
                    'user': anomaly.get('user', 'Unknown'),
                    'src_ip': anomaly.get('src_ip', 'Unknown'),
                    'reasons': anomaly.get('anomaly_reasons', [])
                })
            
            # Create AI prompt
            prompt = f"""
            You are a cybersecurity analyst. Generate a AI Analysis for a SOC report.
            
            Context:
            - Total log entries analyzed: {len(log_entries)}
            - Anomalies detected: {len(anomalies)}
            - Threat level: {threat_level}
            
            Sample anomalies:
            {sample_anomalies}
            
            Requirements:
            1. Write a clear, professional AI Analysis summary (4-5 sentences)
            2. Focus on business impact and risk assessment
            3. Use cybersecurity terminology appropriately
            4. Keep it concise but informative
            5. No technical jargon that users wouldn't understand
            6. Strictly No symbols(stars, asterisks, hashes, etc) in text
            
            Format: Professional business writing style
            """
            
            # Generate response directly with Gemini
            response = self.model.generate_content(prompt)
            
            if response and response.text:
                summary = response.text.strip()
                # Clean up any markdown or extra formatting
                if summary.startswith('```'):
                    summary = summary.split('\n', 1)[1] if '\n' in summary else summary
                if summary.endswith('```'):
                    summary = summary.rsplit('\n', 1)[0] if '\n' in summary else summary
                
                print("Gemini AI summary generated successfully")
                return summary
            else:
                print(" Gemini AI returned empty response")
                return None
                
        except Exception as e:
            print(f" Gemini AI generation failed: {e}")
            return None
    
    def _generate_template_summary(self, log_entries, anomalies, threat_level):
        """Generate fallback summary using professional templates"""
        total_entries = len(log_entries)
        total_anomalies = len(anomalies)
        anomaly_percentage = (total_anomalies / total_entries * 100) if total_entries > 0 else 0
        
        # Determine severity and actions based on anomaly percentage
        if total_anomalies == 0:
            severity_assessment = "no security concerns"
            action_required = "routine monitoring"
            business_impact = "normal operations"
            recommendation = "Continue standard security monitoring protocols."
        elif anomaly_percentage <= 25:
            severity_assessment = "minor security concerns"
            action_required = "routine monitoring and investigation"
            business_impact = "low risk to operations"
            recommendation = "Implement enhanced monitoring and investigate identified anomalies."
        elif anomaly_percentage <= 50:
            severity_assessment = "moderate security threats"
            action_required = "immediate attention from SOC team"
            business_impact = "moderate risk to business operations"
            recommendation = "Activate incident response procedures and conduct thorough investigation."
        else:
            severity_assessment = "critical security incidents"
            action_required = "immediate emergency response and containment"
            business_impact = "high risk to business continuity"
            recommendation = "Implement emergency containment measures and activate crisis response team."
        
        # Select and format template
        template = random.choice(self.soc_templates['AI Analysis'])
        return template.format(
            total_entries=total_entries,
            total_anomalies=total_anomalies,
            anomaly_percentage=anomaly_percentage,
            threat_level=threat_level,
            severity_assessment=severity_assessment,
            action_required=action_required,
            business_impact=business_impact,
            recommendation=recommendation
        )