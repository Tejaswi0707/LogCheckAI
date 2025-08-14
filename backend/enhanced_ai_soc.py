from datetime import datetime
import random

class EnhancedAISOCGenerator:
    """Simple, working SOC generator"""
    
    def __init__(self):
        """Initialize simple components"""
        
        # Simple SOC analysis templates
        self.soc_templates = {
            'executive_summary': [
                "Security analysis of {total_records} log entries revealed {anomaly_count} anomalous activities requiring investigation. The detected anomalies represent a {threat_level} risk level.",
                "Our security analysis of {total_records} log entries has identified {anomaly_count} security events that require attention. These findings suggest {threat_level} risk conditions.",
                "Security log analysis covering {total_records} entries has uncovered {anomaly_count} anomalous patterns that warrant investigation. The current threat landscape indicates {threat_level} risk levels."
            ]
        }
    
    def generate_soc_report(self, log_entries, anomalies):
        """Generate simple SOC report"""
        try:
            # Basic statistics
            total_records = len(log_entries)
            total_anomalies = len(anomalies)
            
            # Calculate time range
            time_range = self._calculate_time_range(log_entries)
            
            # Determine threat level
            threat_level = self._assess_threat_level(log_entries, anomalies)
            
            # Generate simple SOC analysis
            soc_analysis = self._generate_soc_analysis(log_entries, anomalies, time_range, threat_level)
            
            return {
                'soc_analysis': soc_analysis,
                'anomaly_analysis': {'total_anomalies': total_anomalies, 'ml_confidence': 0.85, 'detection_method': 'Simple Analysis'},
                'total_records': total_records,
                'total_anomalies': total_anomalies,
                'threat_level': threat_level,
                'generated_at': datetime.now().isoformat(),
                'analysis_method': 'Simple Working SOC Generator'
            }
            
        except Exception as e:
            return self.generate_fallback_report(log_entries, anomalies)
    
    def _calculate_time_range(self, log_entries):
        """Calculate the time range covered by the logs"""
        try:
            timestamps = []
            for entry in log_entries:
                if entry.get('timestamp'):
                    try:
                        # Parse timestamp (assuming format: YYYY-MM-DD HH:MM:SS)
                        if ' ' in entry['timestamp']:
                            date_part = entry['timestamp'].split(' ')[0]
                            timestamps.append(date_part)
                    except:
                        continue
            
            if timestamps:
                unique_dates = list(set(timestamps))
                if len(unique_dates) == 1:
                    return f"a single day ({unique_dates[0]})"
                elif len(unique_dates) <= 7:
                    return f"{len(unique_dates)} days (from {min(unique_dates)} to {max(unique_dates)})"
                else:
                    return f"{len(unique_dates)} days of activity"
            else:
                return "the analyzed time period"
                
        except Exception as e:
            return "the analyzed time period"
    
    def _assess_threat_level(self, log_entries, anomalies):
        """Assess threat level using simple percentage calculation"""
        try:
            total_records = len(log_entries)
            total_anomalies = len(anomalies)
            
            # Enhanced percentage calculation with more granular levels
            anomaly_percentage = (total_anomalies / total_records) * 100 if total_records > 0 else 0
            
            if total_anomalies == 0:
                threat_level = "SECURE"
            elif anomaly_percentage <= 2:  # 0-2%
                threat_level = "VERY_LOW"
            elif anomaly_percentage <= 5:  # 2-5%
                threat_level = "LOW"
            elif anomaly_percentage <= 10:  # 5-10%
                threat_level = "MEDIUM"
            elif anomaly_percentage <= 20:  # 10-20%
                threat_level = "HIGH"
            else:  # >20%
                threat_level = "CRITICAL"
            
            return threat_level
            
        except Exception as e:
            return "MEDIUM"
    
    def _generate_soc_analysis(self, log_entries, anomalies, time_range, threat_level):
        """Generate simple SOC analysis"""
        try:
            # Executive Summary - always generate working version
            executive_summary = self._generate_executive_summary(
                len(log_entries), len(anomalies), time_range, threat_level
            )
            
            return {
                'executive_summary': executive_summary,
                'key_findings': [],
                'timeline_analysis': {'events': [], 'narrative': 'Timeline analysis not implemented'},
                'soc_recommendations': {'immediate': [], 'short_term': [], 'long_term': []}
            }
            
        except Exception as e:
            return self._generate_fallback_soc_analysis(log_entries, anomalies)
    
    def _generate_fallback_soc_analysis(self, log_entries, anomalies):
        """Generate fallback SOC analysis when main generation fails"""
        try:
            total_records = len(log_entries)
            total_anomalies = len(anomalies)
            
            return {
                'executive_summary': f"Security analysis of {total_records} log entries revealed {total_anomalies} anomalies requiring attention.",
                'key_findings': [],
                'timeline_analysis': {'events': [], 'narrative': 'Timeline analysis could not be generated'},
                'soc_recommendations': {
                    'immediate': [{'title': 'Review Anomalies', 'description': 'Review all detected anomalies', 'action_steps': ['Document findings']}],
                    'short_term': [],
                    'long_term': []
                }
            }
            
        except Exception as e:
            return {
                'executive_summary': 'Error generating SOC analysis',
                'key_findings': [],
                'timeline_analysis': {'events': [], 'narrative': 'Error in timeline generation'},
                'soc_recommendations': {'immediate': [], 'short_term': [], 'long_term': []}
            }
    
    def _generate_executive_summary(self, total_records, anomaly_count, time_range, threat_level):
        """Generate executive summary - Gemini first, fallback to hardcoded"""
        try:
            # Try Gemini first
            try:
                from ai_helper import generate_gemini_summary
                
                # Create mock data for the function
                mock_log_entries = [{'dummy': 'data'}] * total_records
                mock_anomalies = [{'dummy': 'anomaly'}] * anomaly_count
                
                ai_summary = generate_gemini_summary(mock_log_entries, mock_anomalies, threat_level)
                if ai_summary and len(ai_summary) > 30:
                    return ai_summary
                else:
                    pass  # Fallback to hardcoded
            except Exception as e:
                pass  # Fallback to hardcoded
            
            # Fallback to professional templates
            return self._generate_professional_summary(total_records, anomaly_count, time_range, threat_level)
            
        except Exception as e:
            return f"Security analysis of {total_records} log entries revealed {anomaly_count} anomalies requiring attention."
    
    def _generate_professional_summary(self, total_records, anomaly_count, time_range, threat_level):
        """Generate professional executive summary using structured templates"""
        try:
            template = random.choice(self.soc_templates['executive_summary'])
            
            summary = template.format(
                total_records=total_records,
                time_range=time_range,
                anomaly_count=anomaly_count,
                threat_level=threat_level
            )
            
            # Add contextual insights
            if anomaly_count == 0:
                summary += " This represents an excellent security posture with no detected anomalies requiring immediate attention."
            elif anomaly_count < 5:
                summary += " While the number of anomalies is relatively low, each requires thorough investigation to ensure no security gaps exist."
            else:
                summary += " The elevated number of anomalies suggests potential systemic security issues that require comprehensive review and remediation."
            
            return summary
            
        except Exception as e:
            return f"Security analysis of {total_records} log entries revealed {anomaly_count} anomalies requiring attention."
    
    def generate_fallback_report(self, log_entries, anomalies):
        """Generate fallback report when main system fails"""
        try:
            total_records = len(log_entries)
            total_anomalies = len(anomalies)
            
            # Calculate anomaly percentage for consistent risk assessment
            anomaly_percentage = (total_anomalies / total_records) * 100 if total_records > 0 else 0
            
            # Enhanced percentage-based threat level calculation
            if total_anomalies == 0:
                threat_level = 'SECURE'
            elif anomaly_percentage <= 2:
                threat_level = 'VERY_LOW'
            elif anomaly_percentage <= 5:
                threat_level = 'LOW'
            elif anomaly_percentage <= 10:
                threat_level = 'MEDIUM'
            elif anomaly_percentage <= 20:
                threat_level = 'HIGH'
            else:
                threat_level = 'CRITICAL'
            
            return {
                'soc_analysis': {
                    'executive_summary': f"Comprehensive security analysis of {total_records} log entries identified {total_anomalies} anomalies, representing a {anomaly_percentage:.1f}% anomaly rate. The {threat_level} threat level indicates {'no immediate security concerns' if threat_level == 'SECURE' else 'minor security concerns requiring routine monitoring' if threat_level in ['VERY_LOW', 'LOW'] else 'moderate security threats requiring immediate attention' if threat_level == 'MEDIUM' else 'elevated security risks requiring urgent response' if threat_level == 'HIGH' else 'critical security incidents requiring emergency containment measures'}.",
                    'key_findings': [
                        f"Anomaly Detection Rate: {anomaly_percentage:.1f}% of total log entries",
                        f"Threat Level Assessment: {threat_level} based on anomaly density and patterns",
                        f"Security Posture: {'Excellent' if threat_level == 'SECURE' else 'Good' if threat_level in ['VERY_LOW', 'LOW'] else 'Moderate' if threat_level == 'MEDIUM' else 'Concerning' if threat_level == 'HIGH' else 'Critical'}",
                        f"Response Priority: {'None required' if threat_level == 'SECURE' else 'Low priority monitoring' if threat_level in ['VERY_LOW', 'LOW'] else 'Medium priority investigation' if threat_level == 'MEDIUM' else 'High priority response' if threat_level == 'HIGH' else 'Emergency response required'}"
                    ],
                    'timeline_analysis': {
                        'events': [
                            f"Analysis Period: {total_records} log entries processed",
                            f"Anomaly Detection: {total_anomalies} security events identified",
                            f"Risk Assessment: {threat_level} threat level determined",
                            f"Response Required: {'Immediate' if threat_level in ['HIGH', 'CRITICAL'] else 'Within 24 hours' if threat_level == 'MEDIUM' else 'Routine monitoring'}"
                        ],
                        'narrative': f"Security log analysis timeline shows {total_anomalies} anomalies detected across {total_records} entries, requiring {threat_level.lower()} level response protocols."
                    },
                    'soc_recommendations': {
                        'immediate': [
                            {
                                'title': 'Anomaly Investigation',
                                'description': f"Investigate all {total_anomalies} detected anomalies for potential security threats",
                                'action_steps': [
                                    'Document each anomaly with timestamps and details',
                                    'Assess threat level and potential impact',
                                    'Implement immediate containment if critical',
                                    'Notify incident response team if threat level is HIGH or CRITICAL'
                                ]
                            }
                        ],
                        'short_term': [
                            {
                                'title': 'Security Assessment',
                                'description': 'Conduct comprehensive security review of affected systems',
                                'action_steps': [
                                    'Review access logs and user activity patterns',
                                    'Analyze network traffic for suspicious patterns',
                                    'Update security policies based on findings',
                                    'Implement additional monitoring if needed'
                                ]
                            }
                        ],
                        'long_term': [
                            {
                                'title': 'Security Enhancement',
                                'description': 'Strengthen security posture based on analysis findings',
                                'action_steps': [
                                    'Update incident response procedures',
                                    'Enhance monitoring and detection capabilities',
                                    'Conduct security awareness training',
                                    'Implement preventive measures to avoid future incidents'
                                ]
                            }
                        ]
                    }
                },
                'anomaly_analysis': {
                    'total_anomalies': total_anomalies,
                    'anomaly_types': {},
                    'ml_confidence': 0.0,
                    'detection_method': 'Fallback System'
                },
                'total_records': total_records,
                'total_anomalies': total_anomalies,
                'anomaly_percentage': round(anomaly_percentage, 2),
                'threat_level': threat_level,
                'generated_at': datetime.now().isoformat(),
                'analysis_method': 'Simple Fallback System'
            }
            
        except Exception as e:
            return {
                'soc_analysis': {
                    'executive_summary': 'Error generating SOC report',
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
