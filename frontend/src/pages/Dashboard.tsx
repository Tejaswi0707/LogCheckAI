import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { API_BASE_URL } from '../config';

const Dashboard = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadStatus, setUploadStatus] = useState<string>('');
  const [isProcessing, setIsProcessing] = useState(false);
  const navigate = useNavigate();

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      // Check file type
      const fileExtension = file.name.split('.').pop()?.toLowerCase();
      if (fileExtension !== 'txt' && fileExtension !== 'log') {
        setUploadStatus('Please select a .txt or .log file only.');
        return;
      }
      
      // Check file size (10MB = 10 * 1024 * 1024 bytes)
      if (file.size > 10 * 1024 * 1024) {
        setUploadStatus('File is too large. Maximum size allowed is 10MB.');
        return;
      }
      
      setSelectedFile(file);
      setUploadStatus('File selected');
    }
  };

  const handleFileUpload = async () => {
    if (!selectedFile) {
      setUploadStatus('Please select a file first.');
      return;
    }

    setIsProcessing(true);
    setUploadStatus('Processing file...');

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);

      const response = await fetch(`${API_BASE_URL}/upload-simple`, {
        method: 'POST',
        body: formData,
      });

      if (response.ok) {
        const data = await response.json();
        setUploadStatus('File processed successfully! Redirecting to results...');
        
        // Store the result data in localStorage for AnomalyResults page
        localStorage.setItem('uploadResult', JSON.stringify(data));
        
        // Redirect to AnomalyResults page after a short delay
        setTimeout(() => {
          navigate('/anomaly-results');
        }, 1000);
        
      } else {
        const errorData = await response.json();
        setUploadStatus(`Upload failed: ${errorData.message || 'Unknown error'}`);
      }
    } catch (error: any) {
      setUploadStatus(`Upload failed: ${error.message}`);
    } finally {
      setIsProcessing(false);
    }
  };

  const getStatusClass = () => {
    if (uploadStatus.includes('successfully')) return 'status-message status-success';
    if (uploadStatus.includes('selected') || uploadStatus.includes('Processing')) return 'status-message status-warning';
    return 'status-message status-error';
  };

  return (
    <div className="dashboard-container">
      <h1>Dashboard</h1>
      
      <div className="upload-section">
        <h2 className="upload-title">Upload File</h2>
        <div className="form-group">
          <input
            type="file"
            accept=".txt,.log"
            onChange={handleFileSelect}
            className="file-input"
          />
          <p className="file-info">
            Select a .txt or .log file to upload. Maximum size: 10MB
          </p>
        
          <p className="file-note">
            Note: Mandatory fields to have (timestamp, src_ip, user, url, action)
          </p>
        </div>
        
        <br />
        
        <button
          onClick={handleFileUpload}
          disabled={!selectedFile || isProcessing}
          className="upload-button"
        >
          {isProcessing ? 'Processing...' : 'Upload File'}
        </button>
        
        {uploadStatus && (
          <div className={getStatusClass()}>
            {uploadStatus}
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;