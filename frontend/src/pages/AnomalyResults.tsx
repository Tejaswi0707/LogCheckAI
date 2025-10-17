//@ts-nocheck
import { useState, useEffect } from 'react';
import { API_BASE_URL } from '../config';




const AnomalyResults = () => {
  const [uploadResult, setUploadResult] = useState<any>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [entriesPerPage] = useState(10);
  const [activeTab, setActiveTab] = useState('summary');
  const [fromTimestamp, setfromTimestamp]=useState("");
  const [toTimestamp, settoTimestamp]=useState("");
  const [filteredData, setfilteredData]=useState<any[]>([]);
 


  useEffect(() => {
    const storedResult = localStorage.getItem('uploadResult');
    if (storedResult) {
      try {
        setUploadResult(JSON.parse(storedResult));
      } catch (e) {
        setUploadResult(null);
      }
    }
  }, []);

  if (!uploadResult) {
  return (
    <div className="results-container">
      <h1 className="results-title">Log Analysis Results</h1>
      <p className="results-subtitle">Loading analysis data...</p>
    </div>
  );
}

  const fromTime=(event)=>{
    setfromTimestamp(event.target.value);
  }

  const toTime=(event)=>{
    settoTimestamp(event.target.value);
  }

  const toBackendDateTime = (value: string) => {
    if (!value) return value;
    const parts = value.split('T');
    if (parts.length !== 2) return value;
    const date = parts[0];
    let time = parts[1];
    if (time.length === 5) {
      time = time + ':00';
    }
    return `${date} ${time}`;
  }

  const handleRequest=async()=>{
    try {
      if (!fromTimestamp || !toTimestamp) {
        alert('Please select both From and To date/time.');
        return;
      }

      const log_entries = uploadResult.log_entries || [];
      const payload = {
        log_entries,
        fromTimestamp: toBackendDateTime(fromTimestamp),
        toTimestamp: toBackendDateTime(toTimestamp)
      };

      const response = await fetch(`${API_BASE_URL}/filter`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.message || `Request failed with status ${response.status}`);
      }

      const data = await response.json();
      setfilteredData(Array.isArray(data.result) ? data.result : []);
      setCurrentPage(1);
    } catch (e:any) {
      console.error('Filter request failed:', e);
      alert('Filter request failed. Please ensure the backend is running and try again.');
      setfilteredData([]);
    }
  }
  

  // Use backend data directly
  const anomalies = uploadResult.anomalies || [];
  const totalEntries = uploadResult.total_entries || uploadResult.log_entries?.length || 0;
  const totalAnomalies = uploadResult.total_anomalies || anomalies.length;
  const threatLevel = uploadResult.threat_level || 'UNKNOWN';
  const socReport = uploadResult.soc_report || '';


  // Generate timeline summary for SOC analysts
  const generateTimelineSummary = () => {
    if (totalAnomalies === 0) {
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

  

  // Pagination logic (keep as requested)
  const baseEntries = (Array.isArray(filteredData) && filteredData.length > 0)
    ? filteredData
    : (uploadResult.log_entries || []);
  const totalPages = Math.ceil(baseEntries.length / entriesPerPage);
  const startIndex = (currentPage - 1) * entriesPerPage;
  const endIndex = startIndex + entriesPerPage;
  const currentEntries = baseEntries.slice(startIndex, endIndex);
  
  
  return (
    <div className="results-container">
      
      {/* Header */}
      <div className="results-header">
        <h1 className="results-title">Log Analysis Results</h1>
        <p className="results-subtitle">Security analysis report</p>
      </div>
      
      {/* File Information */}
      <div className="file-info-section">
        <div className="stats-grid">
          <div>
            <div className="stat-number">{totalEntries}</div>
            <div className="stat-label">Total Entries</div>
          </div>
          <div>
            <div className="stat-number anomaly">{totalAnomalies}</div>
            <div className="stat-label">Anomalies</div>
          </div>
          <div>
            <div className="stat-number">{threatLevel}</div>
            <div className="stat-label">Threat Level</div>
          </div>
        </div>
      </div>


      {/* Main Content Tabs */}
      <div className="tabs-container">
        
        {/* Tab Navigation */}
        <div className="tab-header">
          <button
            onClick={() => setActiveTab('summary')}
            className={`tab-button ${activeTab === 'summary' ? 'active' : ''}`}
          >
            Log Analysis
          </button>
          <button
            onClick={() => setActiveTab('anomaly-detection')}
            className={`tab-button ${activeTab === 'anomaly-detection' ? 'active' : ''}`}
          >
            Anomaly Detection
          </button>
          <button
            onClick={() => setActiveTab('visualization')}
            className={`tab-button ${activeTab === 'visualization' ? 'active' : ''}`}
          >
            Data Visualization
          </button>
        </div>

        {/* Tab Content */}
        <div className="tab-content">

          {/* Security Summary Tab */}
          {activeTab === 'summary' && (
            <div>
              <h2 className="tab-title">Log Analysis Summary</h2>

              {/* Analysis Summary - Use Backend's soc_report */}
              <div className="analysis-card">
                <h3 className="tab-subtitle">Detailed Analysis</h3>
                <p className="analysis-text">
                  {socReport || 'No detailed analysis available from backend.'}
                </p>
              </div>

              {/* Timeline Summary */}
              <div className="timeline-card">
                <h3 className="tab-subtitle">Timeline Analysis</h3>
                <p className="analysis-text">
                  {generateTimelineSummary()}
                </p>
                
                {/* Key Events - Use Backend's anomalies */}
                {anomalies.length > 0 && (
                  <div>
                    <h4 className="tab-subtitle">Key Security Events:</h4>
                    <div className="events-container">
                      {anomalies
                        .sort((a: any, b: any) => new Date(a.timestamp || 0).getTime() - new Date(b.timestamp || 0).getTime())
                        .map((anomaly: any, index: number) => (
                          <div key={index} className="event-item">
                            <div className="event-header">
                              <strong className="event-title">Event {index + 1}</strong>
                              <span className="event-time">{anomaly.timestamp}</span>
                            </div>
                            <div className="event-details">
                              User: {anomaly.user || 'Unknown'} | IP: {anomaly.src_ip || 'Unknown'}
                            </div>
                            <div className="event-reason">
                              {anomaly.anomaly_reasons}
                            </div>
                          </div>
                        ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Actionable Recommendations */}
              <div className="recommendations-card">
                <h3 className="recommendations-title">Recommended Actions</h3>
                <ul className="recommendations-list">
                  <li>Investigate detected anomalies</li>
                  <li>Review security monitoring thresholds</li>
                  <li>Update incident response procedures if needed</li>
                </ul>
              </div>
            </div>
          )}

          {/* Anomaly Detection Tab */}
          {activeTab === 'anomaly-detection' && (
            <div>
              <h2 className="tab-title">Anomaly Detection Results</h2>

              {/* Anomaly Overview */}
              <div className="anomaly-overview">
                <h3 className="tab-subtitle">Detection Summary</h3>
                <div className="anomaly-grid">
                  <div className="anomaly-stat-card">
                    <div className="anomaly-number">{totalAnomalies}</div>
                    <div className="anomaly-label">Total Anomalies</div>
                  </div>
                  <div className="anomaly-stat-card">
                    <div className="anomaly-number detection-method">Enhanced AI with ML</div>
                    <div className="anomaly-label">Detection Method</div>
                  </div>
                </div>
              </div>

              {/* Log Entries with Anomaly Detection Fields */}
              <div>
                <h3 className="tab-subtitle">Log Entries with Anomaly Detection</h3>

                {/* Pagination Controls */}
                <div className="pagination-controls">
                  <div className="pagination-info">
                    Showing {baseEntries.length === 0 ? 0 : startIndex + 1} to {Math.min(endIndex, baseEntries.length)} of {baseEntries.length} entries
                  </div>
                  <div className="pagination-buttons">
                    <button
                      onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                      disabled={currentPage === 1}
                      className="pagination-button"
                    >
                      Previous
                    </button>
                    <span className="pagination-page">Page {currentPage} of {totalPages}</span>
                    <button
                      onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
                      disabled={currentPage === totalPages}
                      className="pagination-button"
                    >
                      Next
                    </button>
                  </div>
                </div>

                <div className="filter-controls">
        <div className="filter-group">
          <label className="filter-label">From</label>
          <input
            type="datetime-local"
            value={fromTimestamp}
            onChange={fromTime}
            className="filter-input"
          />
        </div>
        <div className="filter-group">
          <label className="filter-label">To</label>
          <input
            type="datetime-local"
            value={toTimestamp}
            onChange={toTime}
            className="filter-input"
          />
        </div>
        <div className="filter-actions">
          <button onClick={handleRequest} className="filter-button">Apply Filter</button>
        </div>
      </div>

                

                {/* Log Entries Table */}
                <div className="table-container">
                  <table className="data-table">
                    <thead className="table-header">
                      <tr>
                        <th>Timestamp</th>
                        <th>User</th>
                        <th>Source IP</th>
                        <th>URL</th>
                        <th>Action</th>
                        <th>Anomaly Status</th>
                        <th>Reason</th>
                        <th>Confidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {currentEntries.map((entry: any, index: number) => (
                        <tr key={index} className={`table-row ${entry.is_anomaly ? 'anomaly' : ''}`}>
                          <td className="table-cell">{entry.timestamp}</td>
                          <td className="table-cell">{entry.user}</td>
                          <td className="table-cell">{entry.src_ip}</td>
                          <td className="table-cell">{entry.url}</td>
                          <td className="table-cell">{entry.action}</td>
                          <td className="table-cell">
                            {entry.is_anomaly ? (
                              <span className="anomaly-badge">ANOMALY</span>
                            ) : (
                              <span className="normal-badge">NORMAL</span>
                            )}
                          </td>
                          <td className="table-cell">
                            {entry.anomaly_reasons && entry.anomaly_reasons.length > 0 
                              ? entry.anomaly_reasons.join('') 
                              : entry.is_anomaly ? 'Anomaly detected' : 'Normal activity'}
                          </td>
                          <td className="table-cell">
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
              <h2 className="tab-title">Data Visualization & Analytics</h2>

              {/* Overview Charts */}
              <div className="visualization-grid">
                <div className="chart-card">
                  <h3 className="chart-title">Activity Distribution</h3>
                  <div className="chart-content">
                    <div className="chart-item">
                      <div className="chart-circle normal">{totalEntries - totalAnomalies}</div>
                      <div className="chart-label">Normal</div>
                    </div>
                    <div className="chart-item">
                      <div className="chart-circle anomaly">{totalAnomalies}</div>
                      <div className="chart-label">Anomalies</div>
                    </div>
                  </div>
                </div>

                {/* Top Users */}
                <div className="chart-card">
                  <h3 className="chart-title">Top Active Users</h3>
                  <div className="users-list">
                    {(() => {
                      const userStats: { [key: string]: number } = {};
                      uploadResult.log_entries?.forEach((entry: any) => {
                        const user = entry.user || 'unknown';
                        userStats[user] = (userStats[user] || 0) + 1;
                      });
                      return Object.entries(userStats)
                        .sort(([,a], [,b]) => (b as number) - (a as number))
                        .slice(0, 5)
                        .map(([user, count], index) => (
                          <div key={index} className="user-item">
                            <span className="user-name">{user}</span>
                            <span className="user-count">{count}</span>
                          </div>
                        ));
                    })()}
                  </div>
                </div>
              </div>

              {/* Time-based Analysis */}
              <div className="time-analysis">
                <h3 className="tab-subtitle">Activity by Time Period</h3>
                <div className="time-chart">
                  <div className="time-bars">
                    {(() => {
                      const timeSlots: { [key: string]: number } = {};
                      uploadResult.log_entries?.forEach((entry: any) => {
                        const hour = entry.timestamp ? new Date(entry.timestamp).getHours() : 0;
                        const timeSlot = `${hour}:00-${hour + 1}:00`;
                        timeSlots[timeSlot] = (timeSlots[timeSlot] || 0) + 1;
                      });
                      return Object.entries(timeSlots)
                        .sort(([a], [b]) => parseInt(a.split(':')[0]) - parseInt(b.split(':')[0]))
                        .map(([timeSlot, count]) => (
                          <div key={timeSlot} className="time-bar">
                            <div 
                              className="time-bar-chart"
                              style={{ height: `${Math.max(20, (count / Math.max(...Object.values(timeSlots))) * 100)}px` }}
                            ></div>
                            <div className="time-label">{timeSlot}</div>
                            <div className="time-count">{count}</div>
                          </div>
                        ));
                    })()}
                  </div>
                </div>
              </div>

              {/* Top IP Addresses */}
              <div>
                <h3 className="tab-subtitle">Top Source IP Addresses</h3>
                <div className="ip-analysis">
                  <div className="ip-list">
                    {(() => {
                      const ipStats: { [key: string]: number } = {};
                      uploadResult.log_entries?.forEach((entry: any) => {
                        const ip = entry.src_ip || 'unknown';
                        ipStats[ip] = (ipStats[ip] || 0) + 1;
                      });
                      return Object.entries(ipStats)
                        .sort(([,a], [,b]) => (b as number) - (a as number))
                        .slice(0, 10)
                        .map(([ip, count], index) => (
                          <div key={index} className="ip-item">
                            <span className="ip-address">{ip}</span>
                            <div className="ip-chart-container">
                              <div className="ip-progress-bar">
                                <div 
                                  className="ip-progress-fill"
                                  style={{ width: `${(count / Math.max(...Object.values(ipStats))) * 100}%` }}
                                ></div>
                              </div>
                              <span className="ip-count">{count}</span>
                            </div>
                          </div>
                        ));
                    })()}
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