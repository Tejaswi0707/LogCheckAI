import { useState, useEffect } from 'react';

const AnomalyResults = () => {
  const [uploadResult, setUploadResult] = useState<any>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [entriesPerPage] = useState(10);
  const [activeTab, setActiveTab] = useState('summary');

  useEffect(() => {
    const storedResult = localStorage.getItem('uploadResult');
    if (storedResult) {
      try {
        setUploadResult(JSON.parse(storedResult));
      } catch (e) {
        // Silently handle localStorage parsing errors
        setUploadResult(null);
      }
    }
  }, []);

  if (!uploadResult) {
    return (
      <div style={{ padding: '20px', textAlign: 'center' }}>
        <h1>Log Analysis Results</h1>
        <p>No analysis data found. Please upload a file from the Dashboard first.</p>
      </div>
    );
  }

  // Pagination logic
  const totalPages = Math.ceil((uploadResult.log_entries?.length || 0) / entriesPerPage);
  const startIndex = (currentPage - 1) * entriesPerPage;
  const endIndex = startIndex + entriesPerPage;
  const currentEntries = uploadResult.log_entries?.slice(startIndex, endIndex) || [];

  // Get anomaly count
  const anomalyCount = uploadResult.log_entries?.filter((entry: any) => entry.is_anomaly)?.length || 0;

  // Get SOC report data
  const socReport = uploadResult.soc_report || {};
  const anomalyAnalysis = socReport.anomaly_analysis || {};

  // Generate detailed analysis text using backend Gemini AI or fallback
  const generateDetailedAnalysis = () => {
    // Check if we have AI-generated summary from backend
    if (socReport?.soc_analysis?.executive_summary) {
              return socReport.soc_analysis.executive_summary;
      }
      
      // Fallback to local generation if no AI summary available
    const totalEntries = uploadResult.log_entries?.length || 0;
    const anomalyRate = totalEntries > 0 ? (anomalyCount / totalEntries * 100) : 0;
    
    // Calculate threat level
    let threatLevel = 'SECURE';
    if (anomalyCount > 0) {
      if (anomalyRate <= 25) {
        threatLevel = 'LOW';
      } else if (anomalyRate <= 50) {
        threatLevel = 'MEDIUM';
      } else {
        threatLevel = 'CRITICAL';
      }
    }
    
    let analysisText = `Log analysis of ${totalEntries} log entries revealed ${anomalyCount} anomalous activities requiring investigation. `;
    
    if (anomalyCount === 0) {
      analysisText += `The system appears to be operating within normal parameters with a ${threatLevel} threat level.`;
    } else if (anomalyRate <= 25) {
      analysisText += `The ${threatLevel} threat level indicates minor concerns requiring routine monitoring.`;
    } else if (anomalyRate <= 50) {
      analysisText += `The ${threatLevel} threat level suggests moderate threats requiring immediate attention.`;
    } else {
      analysisText += `The ${threatLevel} threat level indicates critical incidents requiring emergency response.`;
    }

    // Add user behavior analysis with intelligent thresholds
    const userStats: { [key: string]: number } = {};
    const ipStats: { [key: string]: number } = {};
    uploadResult.log_entries?.forEach((entry: any) => {
      const user = entry.user || 'unknown';
      const ip = entry.src_ip || 'unknown';
      userStats[user] = (userStats[user] || 0) + 1;
      ipStats[ip] = (ipStats[ip] || 0) + 1;
    });

    const avgRequestsPerUser = totalEntries / Object.keys(userStats).length;
    const avgRequestsPerIP = totalEntries / Object.keys(ipStats).length;
    
    // Set thresholds: More conservative for smaller datasets
    // For datasets < 100 records: 5x average is suspicious, 8x average is highly suspicious
    const multiplier = totalEntries < 100 ? 5 : 3;
    const userThreshold = Math.max(5, avgRequestsPerUser * multiplier);
    const ipThreshold = Math.max(5, avgRequestsPerIP * multiplier);
    
    const suspiciousUsers = Object.entries(userStats).filter(([,count]) => (count as number) > userThreshold);
    const suspiciousIPs = Object.entries(ipStats).filter(([,count]) => (count as number) > ipThreshold);

    if (suspiciousUsers.length > 0) {
      const topSuspiciousUser = suspiciousUsers.sort(([,a], [,b]) => (b as number) - (a as number))[0];
      analysisText += ` User activity analysis shows that '${topSuspiciousUser[0]}' generated ${topSuspiciousUser[1]} requests (${(topSuspiciousUser[1] as number / avgRequestsPerUser).toFixed(1)}x above average), which may indicate either legitimate high-usage patterns or potential account compromise requiring investigation.`;
    }

    if (suspiciousIPs.length > 0) {
      const topSuspiciousIP = suspiciousIPs.sort(([,a], [,b]) => (b as number) - (a as number))[0];
      analysisText += ` Network analysis reveals that IP address ${topSuspiciousIP[0]} generated ${topSuspiciousIP[1]} requests (${(topSuspiciousIP[1] as number / avgRequestsPerIP).toFixed(1)}x above average), suggesting either normal business operations or potential reconnaissance activities that warrant monitoring.`;
    }

    // Add threat correlation - only count anomalies
    if (anomalyCount > 0) {
      let totalThreats = 0;
      let validThreatCounts = 0;
      
      // Only process anomaly records for threat correlation
      uploadResult.log_entries?.forEach((entry: any) => {
        if (entry.is_anomaly && entry.threat_count !== undefined && entry.threat_count !== null) {
          const threatCount = Number(entry.threat_count);
          if (!isNaN(threatCount) && threatCount >= 0 && threatCount < 1000) {
            totalThreats += threatCount;
            validThreatCounts++;
          }
        }
      });
      
      if (validThreatCounts > 0 && totalThreats > 0) {
        analysisText += ` Threat correlation analysis identified ${totalThreats} total threat indicators across ${validThreatCounts} anomalous entries, suggesting potential coordinated attack activity or systemic security vulnerabilities that require immediate attention from the incident response team.`;
      } else if (anomalyCount > 5) {
        analysisText += ` The high number of anomalies suggests potential coordinated attack activity or systemic security vulnerabilities that require immediate attention from the incident response team.`;
      }
    }

    return analysisText;
  };

  // Generate actionable recommendations
  const generateRecommendations = () => {
    if (anomalyCount === 0) {
      return [
        "Continue current security monitoring practices",
        "Maintain existing security controls effectiveness",
        "Schedule regular security posture reviews"
      ];
    } else if (anomalyCount < 5) {
      return [
        "Investigate each anomaly to determine root cause",
        "Review security monitoring thresholds",
        "Update incident response procedures if needed",
        "Document findings for future reference"
      ];
    } else if (anomalyCount < 15) {
      return [
        "Activate incident response team for coordination",
        "Implement enhanced monitoring for affected systems",
        "Review and update security policies",
        "Conduct security awareness training",
        "Consider additional security controls"
      ];
    } else {
      return [
        "Immediately activate emergency response procedures",
        "Isolate affected systems and networks",
        "Engage senior management and legal teams",
        "Notify relevant authorities if required",
        "Implement containment measures",
        "Begin comprehensive security assessment"
      ];
    }
  };

  // Generate timeline summary for SOC analysts
  const generateTimelineSummary = () => {
    if (anomalyCount === 0) {
      return "The security timeline shows consistent normal activity throughout the analysis period with no detected anomalies. This indicates a stable security environment with effective controls in place.";
    }

    // Get all anomalies sorted by timestamp
    const anomalies = uploadResult.log_entries
      ?.filter((entry: any) => entry.is_anomaly)
      .sort((a: any, b: any) => new Date(a.timestamp || 0).getTime() - new Date(b.timestamp || 0).getTime()) || [];

    if (anomalies.length === 0) {
      return "Timeline analysis could not be completed due to missing timestamp data.";
    }

    const firstAnomaly = anomalies[0];
    const lastAnomaly = anomalies[anomalies.length - 1];
    
    let timelineText = `The security timeline reveals a progression of events beginning at ${firstAnomaly.timestamp || 'unknown time'} and continuing through ${lastAnomaly.timestamp || 'unknown time'}. `;
    
    if (anomalies.length === 1) {
      timelineText += "A single security anomaly was detected during this period, requiring investigation to determine its scope and impact.";
    } else if (anomalies.length <= 5) {
      timelineText += `The detection of ${anomalies.length} anomalies over this time period suggests either isolated security incidents or potential systemic issues requiring attention.`;
    } else {
      timelineText += `The detection of ${anomalies.length} anomalies over this time period indicates either coordinated attack activity or widespread security issues requiring immediate investigation and response.`;
    }

    // Add temporal pattern analysis
    const timeGaps = [];
    for (let i = 1; i < anomalies.length; i++) {
      const prevTime = new Date(anomalies[i-1].timestamp || 0).getTime();
      const currTime = new Date(anomalies[i].timestamp || 0).getTime();
      const gapMinutes = Math.round((currTime - prevTime) / (1000 * 60));
      if (gapMinutes > 0) timeGaps.push(gapMinutes);
    }

    if (timeGaps.length > 0) {
      const avgGap = Math.round(timeGaps.reduce((a, b) => a + b, 0) / timeGaps.length);
      if (avgGap < 10) {
        timelineText += " The rapid succession of events (average gap of " + avgGap + " minutes) suggests potential automated attack patterns or system compromise.";
      } else if (avgGap < 60) {
        timelineText += " The moderate timing between events (average gap of " + avgGap + " minutes) suggests either manual reconnaissance or intermittent attack attempts.";
      } else {
        timelineText += " The extended intervals between events (average gap of " + avgGap + " minutes) suggest either low-frequency attack attempts or ongoing security issues.";
      }
    }

    timelineText += " Understanding this sequence is crucial for determining the scope of any potential breach and implementing appropriate containment measures.";

    return timelineText;
  };

  // Generate simple anomaly reason in plain English
  const generateAnomalyReason = (entry: any) => {
    if (!entry.is_anomaly) return "Normal activity";
    
    // If we have specific anomaly reasons from the backend, use them
    if (entry.anomaly_reasons && entry.anomaly_reasons.length > 0) {
      // Convert technical reasons to simple English and remove duplicates
      const reasonMap = new Map();
      
      entry.anomaly_reasons.forEach((reason: string) => {
        let simpleReason = "";
        
        // Preserve ML detection messages
        if (reason.includes('🤖 ML Detected:')) {
          simpleReason = reason; // Keep ML messages as-is
        }
        // Convert common technical terms to simple English
        else if (reason.toLowerCase().includes('malware')) simpleReason = "Malware detected";
        else if (reason.toLowerCase().includes('phishing')) simpleReason = "Phishing attempt";
        else if (reason.toLowerCase().includes('brute')) simpleReason = "Brute force attack";
        else if (reason.toLowerCase().includes('sql')) simpleReason = "SQL injection attempt";
        else if (reason.toLowerCase().includes('xss')) simpleReason = "XSS attack attempt";
        else if (reason.toLowerCase().includes('command')) simpleReason = "Command injection attempt";
        else if (reason.toLowerCase().includes('directory')) simpleReason = "Directory traversal attempt";
        else if (reason.toLowerCase().includes('file')) simpleReason = "Suspicious file upload";
        else if (reason.toLowerCase().includes('data')) simpleReason = "Data exfiltration attempt";
        else if (reason.toLowerCase().includes('admin')) simpleReason = "Unauthorized admin access";
        else if (reason.toLowerCase().includes('unusual')) simpleReason = "Unusual activity pattern";
        else if (reason.toLowerCase().includes('frequency')) simpleReason = "High request frequency";
        else if (reason.toLowerCase().includes('threshold')) simpleReason = "Threshold exceeded";
        else if (reason.toLowerCase().includes('baseline')) simpleReason = "Baseline deviation";
        else if (reason.toLowerCase().includes('outlier')) simpleReason = "Statistical outlier";
        else if (reason.toLowerCase().includes('error') && entry.http_status) {
          simpleReason = `HTTP error: Status ${entry.http_status}`;
        }
        else if (reason.length < 50 && !reason.includes('_') && !reason.includes('.')) {
          simpleReason = reason;
        }
        else {
          simpleReason = "Security violation detected";
        }
        
        // Only add if not already present
        if (simpleReason && !reasonMap.has(simpleReason)) {
          reasonMap.set(simpleReason, true);
        }
      });
      
      const uniqueReasons = Array.from(reasonMap.keys());
      return uniqueReasons.length > 0 ? uniqueReasons.join("; ") : "Security violation detected";
    }
    
    // Generate reason based on entry data if no specific reasons provided
    const reasons = [];
    
    if (entry.threat_count > 0) reasons.push(`Threat indicators: ${entry.threat_count}`);
    if (entry.malware_count > 0) reasons.push(`Malware detected: ${entry.malware_count}`);
    if (entry.action === 'blocked') reasons.push("Access blocked");
    if (entry.http_status >= 400) reasons.push(`HTTP error: ${entry.http_status}`);
    if (entry.ssl_cert_validity_days === 0) reasons.push("Invalid SSL certificate");
    
    if (reasons.length > 0) {
      return reasons.join("; ");
    }
    
    return "Security violation detected";
  };

  // Generate visualization data
  const generateVisualizationData = () => {
    const totalEntries = uploadResult.log_entries?.length || 0;
    const normalCount = totalEntries - anomalyCount;
    
    // Time-based analysis
    const timeSlots: { [key: string]: number } = {};
    const userActivity: { [key: string]: number } = {};
    const ipActivity: { [key: string]: number } = {};
    
    uploadResult.log_entries?.forEach((entry: any) => {
      // Time slots (hourly)
      const hour = entry.timestamp ? new Date(entry.timestamp).getHours() : 0;
      const timeSlot = `${hour}:00-${hour + 1}:00`;
      timeSlots[timeSlot] = (timeSlots[timeSlot] || 0) + 1;
      
      // User activity
      const user = entry.user || 'Unknown';
      userActivity[user] = (userActivity[user] || 0) + 1;
      
      // IP activity
      const ip = entry.src_ip || 'Unknown';
      ipActivity[ip] = (ipActivity[ip] || 0) + 1;
    });

    return {
      timeSlots,
      userActivity,
      ipActivity,
      normalCount,
      anomalyCount,
      totalEntries
    };
  };

  const vizData = generateVisualizationData();

  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '20px', fontFamily: 'system-ui, -apple-system, sans-serif' }}>
      
      {/* Header */}
      <div style={{ marginBottom: '30px' }}>
        <h1 style={{ margin: '0 0 10px 0', fontSize: '28px', fontWeight: '500', color: '#333' }}>
          Log Analysis Results
        </h1>
        <p style={{ margin: '0', fontSize: '16px', color: '#666' }}>
          Security analysis report for {uploadResult.filename}
        </p>
      </div>
      
      {/* File Information */}
      <div style={{ 
        backgroundColor: '#f8f9fa', 
        padding: '20px', 
        borderRadius: '6px', 
        marginBottom: '25px', 
        border: '1px solid #e9ecef'
      }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '20px' }}>
          <div>
            <div style={{ fontSize: '24px', fontWeight: '500', color: '#333' }}>{uploadResult.log_entries?.length || 0}</div>
            <div style={{ fontSize: '14px', color: '#666' }}>Total Entries</div>
          </div>
                    <div>
            <div style={{ fontSize: '24px', fontWeight: '500', color: '#dc3545' }}>{anomalyCount}</div>
            <div style={{ fontSize: '14px', color: '#666' }}>Anomalies</div>
          </div>
          <div>
            <div style={{ fontSize: '20px', fontWeight: '500', color: '#333' }}>
              {(() => {
                if (anomalyCount === 0) return 'SECURE';
                const percentage = (anomalyCount / (uploadResult.log_entries?.length || 1)) * 100;
                if (percentage <= 25) return 'LOW';
                if (percentage <= 50) return 'MEDIUM';
                return 'CRITICAL';
              })()}
            </div>
            <div style={{ fontSize: '14px', color: '#666' }}>Threat Level</div>
          </div>
        </div>
      </div>

      {/* Main Content Tabs */}
      <div style={{ backgroundColor: 'white', borderRadius: '6px', border: '1px solid #e9ecef', overflow: 'hidden' }}>
        
        {/* Tab Navigation */}
        <div style={{ display: 'flex', borderBottom: '1px solid #e9ecef', backgroundColor: '#f8f9fa' }}>
          <button
            onClick={() => setActiveTab('summary')}
            style={{
              padding: '15px 25px',
              border: 'none',
              backgroundColor: activeTab === 'summary' ? '#007bff' : 'transparent',
              color: activeTab === 'summary' ? 'white' : '#495057',
              cursor: 'pointer',
              fontSize: '14px',
              fontWeight: '500',
              borderRight: '1px solid #e9ecef'
            }}
          >
            Log Analysis
          </button>
          <button
            onClick={() => setActiveTab('anomaly-detection')}
            style={{
              padding: '15px 25px',
              border: 'none',
              backgroundColor: activeTab === 'anomaly-detection' ? '#007bff' : 'transparent',
              color: activeTab === 'anomaly-detection' ? 'white' : '#495057',
              cursor: 'pointer',
              fontSize: '14px',
              fontWeight: '500',
              borderRight: '1px solid #e9ecef'
            }}
          >
            Anomaly Detection
          </button>
          <button
            onClick={() => setActiveTab('visualization')}
            style={{
              padding: '15px 25px',
              border: 'none',
              backgroundColor: activeTab === 'visualization' ? '#007bff' : 'transparent',
              color: activeTab === 'visualization' ? 'white' : '#495057',
              cursor: 'pointer',
              fontSize: '14px',
              fontWeight: '500'
            }}
          >
            Data Visualization
          </button>
        </div>

        {/* Tab Content */}
        <div style={{ padding: '25px' }}>

          {/* Security Summary Tab */}
          {activeTab === 'summary' && (
            <div>
              <h2 style={{ margin: '0 0 25px 0', color: '#333', fontSize: '22px', fontWeight: '500' }}>
                Log Analysis Summary
              </h2>

              {/* Analysis Summary */}
              <div style={{ 
                padding: '20px', 
                backgroundColor: '#f8f9fa', 
                borderRadius: '6px', 
                border: '1px solid #e9ecef',
                lineHeight: '1.6',
                marginBottom: '25px'
              }}>
                <h3 style={{ margin: '0 0 15px 0', color: '#333', fontSize: '18px', fontWeight: '500' }}>
                  Detailed Analysis
          </h3>
                <p style={{ margin: '0', fontSize: '15px', color: '#333' }}>
                  {generateDetailedAnalysis()}
                </p>
              </div>

              {/* Timeline Summary */}
              <div style={{ 
                padding: '20px', 
                backgroundColor: 'white', 
                borderRadius: '6px', 
                border: '1px solid #e9ecef',
                lineHeight: '1.6',
                marginBottom: '25px'
              }}>
                <h3 style={{ margin: '0 0 20px 0', color: '#333', fontSize: '18px', fontWeight: '500' }}>
                  Timeline Analysis
                </h3>
                <p style={{ margin: '0 0 20px 0', fontSize: '15px', color: '#333' }}>
                  {generateTimelineSummary()}
                </p>
                
                {/* Key Events */}
                {uploadResult.log_entries?.filter((entry: any) => entry.is_anomaly).length > 0 && (
                  <div>
                    <h4 style={{ margin: '0 0 15px 0', color: '#333', fontSize: '16px', fontWeight: '500' }}>
                      Key Security Events:
                    </h4>
                    <div style={{ maxHeight: '250px', overflowY: 'auto' }}>
                      {uploadResult.log_entries
                        ?.filter((entry: any) => entry.is_anomaly)
                        .sort((a: any, b: any) => new Date(a.timestamp || 0).getTime() - new Date(b.timestamp || 0).getTime())
                        .map((entry: any, index: number) => (
                          <div key={index} style={{ 
                            padding: '12px', 
                            marginBottom: '8px', 
                            backgroundColor: '#f8f9fa', 
                            borderRadius: '4px', 
                            border: '1px solid #e9ecef'
                          }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                              <strong style={{ color: '#333', fontSize: '14px' }}>
                                Event {index + 1}
                              </strong>
                              <span style={{ fontSize: '13px', color: '#666' }}>
                                {entry.timestamp}
                      </span>
                            </div>
                            <div style={{ fontSize: '13px', color: '#666', marginBottom: '4px' }}>
                              User: {entry.user || 'Unknown'} | IP: {entry.src_ip || 'Unknown'}
                            </div>
                            <div style={{ fontSize: '13px', color: '#333' }}>
                              {generateAnomalyReason(entry)}
                            </div>
                          </div>
                        ))}
                    </div>
                            </div>
                          )}
                        </div>

              {/* Actionable Recommendations */}
              <div style={{ 
                padding: '20px', 
                backgroundColor: '#fff3e0', 
                borderRadius: '6px', 
                border: '1px solid #ffcc02',
                lineHeight: '1.6'
              }}>
                <h3 style={{ margin: '0 0 15px 0', color: '#e65100', fontSize: '18px', fontWeight: '500' }}>
                  Recommended Actions
                </h3>
                <ul style={{ margin: '0', paddingLeft: '20px' }}>
                  {generateRecommendations().map((rec, index) => (
                    <li key={index} style={{ marginBottom: '8px', fontSize: '15px', color: '#bf360c' }}>
                      {rec}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}

          {/* Anomaly Detection Tab */}
          {activeTab === 'anomaly-detection' && (
            <div>
              <h2 style={{ margin: '0 0 25px 0', color: '#333', fontSize: '22px', fontWeight: '500' }}>
                Anomaly Detection Results
              </h2>

              {/* Anomaly Overview */}
              <div style={{ marginBottom: '25px', padding: '20px', backgroundColor: '#f8f9fa', borderRadius: '6px', border: '1px solid #e9ecef' }}>
                <h3 style={{ margin: '0 0 20px 0', color: '#333', fontSize: '18px', fontWeight: '500' }}>
                  Detection Summary
                </h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '20px' }}>
                  <div style={{ textAlign: 'center', padding: '15px', backgroundColor: 'white', borderRadius: '4px', border: '1px solid #e9ecef' }}>
                    <div style={{ fontSize: '28px', fontWeight: '500', color: '#dc3545' }}>{anomalyCount}</div>
                    <div style={{ fontSize: '13px', color: '#666' }}>Total Anomalies</div>
                  </div>

                  <div style={{ textAlign: 'center', padding: '15px', backgroundColor: 'white', borderRadius: '4px', border: '1px solid #e9ecef' }}>
                    <div style={{ fontSize: '16px', fontWeight: '500', color: '#333' }}>
                      {anomalyAnalysis.detection_method || 'Enhanced AI with ML'}
                    </div>
                    <div style={{ fontSize: '13px', color: '#666' }}>Detection Method</div>
                  </div>
                </div>
          </div>

              {/* Log Entries with Anomaly Detection Fields */}
              <div>
                <h3 style={{ margin: '0 0 20px 0', color: '#333', fontSize: '18px', fontWeight: '500' }}>
                  Log Entries with Anomaly Detection
                </h3>

                {/* Pagination Controls */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                  <div style={{ fontSize: '14px', color: '#666' }}>
                    Showing {startIndex + 1} to {Math.min(endIndex, uploadResult.log_entries?.length || 0)} of {uploadResult.log_entries?.length || 0} entries
                  </div>
                  <div style={{ display: 'flex', gap: '8px' }}>
              <button
                      onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                disabled={currentPage === 1}
                style={{
                  padding: '8px 16px',
                        border: '1px solid #e9ecef',
                  backgroundColor: currentPage === 1 ? '#f8f9fa' : 'white',
                        color: currentPage === 1 ? '#ccc' : '#333',
                  borderRadius: '4px',
                        cursor: currentPage === 1 ? 'not-allowed' : 'pointer',
                        fontSize: '13px'
                }}
              >
                Previous
              </button>
                    <span style={{ padding: '8px 16px', border: '1px solid #e9ecef', backgroundColor: '#f8f9fa', borderRadius: '4px', fontSize: '13px' }}>
                Page {currentPage} of {totalPages}
              </span>
              <button
                      onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
                disabled={currentPage === totalPages}
                style={{
                  padding: '8px 16px',
                        border: '1px solid #e9ecef',
                  backgroundColor: currentPage === totalPages ? '#f8f9fa' : 'white',
                        color: currentPage === totalPages ? '#ccc' : '#333',
                  borderRadius: '4px',
                        cursor: currentPage === totalPages ? 'not-allowed' : 'pointer',
                        fontSize: '13px'
                }}
              >
                Next
              </button>
            </div>
                </div>

                {/* Log Entries Table with Anomaly Fields */}
                <div style={{ overflowX: 'auto', backgroundColor: 'white', borderRadius: '4px', border: '1px solid #e9ecef' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ backgroundColor: '#f8f9fa' }}>
                        <th style={{ padding: '12px', textAlign: 'left', border: '1px solid #e9ecef', fontSize: '13px', fontWeight: '500', color: '#333' }}>Timestamp</th>
                        <th style={{ padding: '12px', textAlign: 'left', border: '1px solid #e9ecef', fontSize: '13px', fontWeight: '500', color: '#333' }}>User</th>
                        <th style={{ padding: '12px', textAlign: 'left', border: '1px solid #e9ecef', fontSize: '13px', fontWeight: '500', color: '#333' }}>Source IP</th>
                        <th style={{ padding: '12px', textAlign: 'left', border: '1px solid #e9ecef', fontSize: '13px', fontWeight: '500', color: '#333' }}>URL</th>
                        <th style={{ padding: '12px', textAlign: 'left', border: '1px solid #e9ecef', fontSize: '13px', fontWeight: '500', color: '#333' }}>Action</th>
                        <th style={{ padding: '12px', textAlign: 'left', border: '1px solid #e9ecef', fontSize: '13px', fontWeight: '500', color: '#333' }}>Anomaly Status</th>
                        <th style={{ padding: '12px', textAlign: 'left', border: '1px solid #e9ecef', fontSize: '13px', fontWeight: '500', color: '#333' }}>Reason</th>
                        <th style={{ padding: '12px', textAlign: 'left', border: '1px solid #e9ecef', fontSize: '13px', fontWeight: '500', color: '#333' }}>Confidence</th>

                      </tr>
                    </thead>
                    <tbody>
                      {currentEntries.map((entry: any, index: number) => (
                        <tr key={index} style={{ 
                          backgroundColor: entry.is_anomaly ? '#f8f9fa' : 'white',
                          borderBottom: '1px solid #e9ecef'
                        }}>
                          <td style={{ padding: '12px', border: '1px solid #e9ecef', fontSize: '13px', color: '#333' }}>{entry.timestamp}</td>
                          <td style={{ padding: '12px', border: '1px solid #e9ecef', fontSize: '13px', color: '#333' }}>{entry.user}</td>
                          <td style={{ padding: '12px', border: '1px solid #e9ecef', fontSize: '13px', color: '#333' }}>{entry.src_ip}</td>
                          <td style={{ padding: '12px', border: '1px solid #e9ecef', fontSize: '13px', color: '#333' }}>{entry.url}</td>
                          <td style={{ padding: '12px', border: '1px solid #e9ecef', fontSize: '13px', color: '#333' }}>{entry.action}</td>
                          <td style={{ padding: '12px', border: '1px solid #e9ecef', fontSize: '13px' }}>
                            {entry.is_anomaly ? (
                              <span style={{ 
                                padding: '4px 8px', 
                                backgroundColor: '#dc3545', 
                                color: 'white',
                                borderRadius: '4px',
                                fontSize: '12px',
                                fontWeight: '500'
                              }}>
                                ANOMALY
                              </span>
                            ) : (
                              <span style={{ 
                                padding: '4px 8px', 
                                backgroundColor: '#28a745', 
                                color: 'white', 
                                borderRadius: '4px',
                                fontSize: '12px',
                                fontWeight: '500'
                              }}>
                                NORMAL
                              </span>
                            )}
                          </td>
                          <td style={{ padding: '12px', border: '1px solid #e9ecef', fontSize: '13px', color: '#333' }}>
                            {generateAnomalyReason(entry)}
                          </td>
                          <td style={{ padding: '12px', border: '1px solid #e9ecef', fontSize: '13px', color: '#333' }}>
                            {entry.is_anomaly ? 
                              Math.round((entry.anomaly_confidence || 0.8) * 100) + '%' : 
                              'N/A'
                            }
                          </td>

                        </tr>
                      ))}
                    </tbody>
                  </table>
            </div>
          </div>
        </div>
      )}

          {/* Data Visualization Tab */}
          {activeTab === 'visualization' && (
            <div>
              <h2 style={{ margin: '0 0 25px 0', color: '#333', fontSize: '22px', fontWeight: '500' }}>
                Data Visualization & Analytics
              </h2>

              {/* Overview Charts */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '25px', marginBottom: '30px' }}>
                {/* Activity Distribution */}
                <div style={{ padding: '20px', backgroundColor: '#f8f9fa', borderRadius: '6px', border: '1px solid #e9ecef' }}>
                  <h3 style={{ margin: '0 0 20px 0', color: '#333', fontSize: '18px', fontWeight: '500' }}>
                    Activity Distribution
                  </h3>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-around' }}>
                    <div style={{ textAlign: 'center' }}>
                      <div style={{ 
                        width: '80px', 
                        height: '80px', 
                        borderRadius: '50%', 
                        backgroundColor: '#28a745',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: 'white',
                        fontSize: '16px',
                        fontWeight: '500',
                        margin: '0 auto 10px auto'
                      }}>
                        {vizData.normalCount}
                      </div>
                      <div style={{ fontSize: '14px', color: '#666' }}>Normal</div>
                    </div>
                    <div style={{ textAlign: 'center' }}>
                      <div style={{ 
                        width: '80px', 
                        height: '80px', 
                        borderRadius: '50%', 
                        backgroundColor: '#dc3545',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: 'white',
                        fontSize: '16px',
                        fontWeight: '500',
                        margin: '0 auto 10px auto'
                      }}>
                        {vizData.anomalyCount}
                      </div>
                      <div style={{ fontSize: '14px', color: '#666' }}>Anomalies</div>
                    </div>
                  </div>
                </div>

                {/* Top Users */}
                <div style={{ padding: '20px', backgroundColor: '#f8f9fa', borderRadius: '6px', border: '1px solid #e9ecef' }}>
                  <h3 style={{ margin: '0 0 20px 0', color: '#333', fontSize: '18px', fontWeight: '500' }}>
                    Top Active Users
                  </h3>
                  <div style={{ maxHeight: '150px', overflowY: 'auto' }}>
                    {Object.entries(vizData.userActivity)
                      .sort(([,a], [,b]) => (b as number) - (a as number))
                      .slice(0, 5)
                      .map(([user, count], index) => (
                        <div key={index} style={{ 
                          display: 'flex', 
                          justifyContent: 'space-between', 
                          alignItems: 'center',
                          padding: '8px 0',
                          borderBottom: index < 4 ? '1px solid #e9ecef' : 'none'
                        }}>
                          <span style={{ fontSize: '14px', color: '#333' }}>{user}</span>
                          <span style={{ fontSize: '14px', color: '#666', fontWeight: '500' }}>{count}</span>
                        </div>
                      ))}
                  </div>
                </div>
              </div>

              {/* Time-based Analysis */}
              <div style={{ marginBottom: '30px' }}>
                <h3 style={{ margin: '0 0 20px 0', color: '#333', fontSize: '18px', fontWeight: '500' }}>
                  Activity by Time Period
                </h3>
                <div style={{ 
                  padding: '20px', 
                  backgroundColor: 'white', 
                  borderRadius: '6px', 
                  border: '1px solid #e9ecef',
                  overflowX: 'auto'
                }}>
                  <div style={{ display: 'flex', gap: '10px', minWidth: 'max-content' }}>
                    {Object.entries(vizData.timeSlots)
                      .sort(([a], [b]) => parseInt(a.split(':')[0]) - parseInt(b.split(':')[0]))
                      .map(([timeSlot, count]) => (
                        <div key={timeSlot} style={{ textAlign: 'center', minWidth: '80px' }}>
                          <div style={{ 
                            height: `${Math.max(20, (count / Math.max(...Object.values(vizData.timeSlots))) * 100)}px`,
                            backgroundColor: '#007bff',
                            borderRadius: '4px 4px 0 0',
                            marginBottom: '5px'
                          }}></div>
                          <div style={{ fontSize: '12px', color: '#666' }}>{timeSlot}</div>
                          <div style={{ fontSize: '14px', fontWeight: '500', color: '#333' }}>{count}</div>
                        </div>
                      ))}
                  </div>
                </div>
              </div>

              {/* Top IP Addresses */}
              <div>
                <h3 style={{ margin: '0 0 20px 0', color: '#333', fontSize: '18px', fontWeight: '500' }}>
                  Top Source IP Addresses
                </h3>
                <div style={{ 
                  padding: '20px', 
                  backgroundColor: 'white', 
                  borderRadius: '6px', 
                  border: '1px solid #e9ecef'
                }}>
                  <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
                    {Object.entries(vizData.ipActivity)
                      .sort(([,a], [,b]) => (b as number) - (a as number))
                      .slice(0, 10)
                      .map(([ip, count], index) => (
                        <div key={index} style={{ 
                          display: 'flex', 
                          justifyContent: 'space-between', 
                          alignItems: 'center',
                          padding: '12px',
                          backgroundColor: index % 2 === 0 ? '#f8f9fa' : 'white',
                          borderRadius: '4px',
                          marginBottom: '8px'
                        }}>
                          <span style={{ fontSize: '14px', color: '#333', fontFamily: 'monospace' }}>{ip}</span>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                            <div style={{ 
                              width: '100px', 
                              height: '8px', 
                              backgroundColor: '#e9ecef', 
            borderRadius: '4px', 
                              overflow: 'hidden'
                            }}>
                              <div style={{ 
                                width: `${(count / Math.max(...Object.values(vizData.ipActivity))) * 100}%`,
                                height: '100%',
                                backgroundColor: '#007bff'
                              }}></div>
                            </div>
                            <span style={{ fontSize: '14px', color: '#666', fontWeight: '500', minWidth: '30px' }}>{count}</span>
                          </div>
                        </div>
                      ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AnomalyResults;
