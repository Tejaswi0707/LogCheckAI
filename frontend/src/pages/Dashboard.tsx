import { useState } from 'react';
import { useNavigate } from 'react-router-dom';

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

      const response = await fetch('http://localhost:5000/upload-simple', {
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

  return (
    <div style={{ maxWidth: '800px', margin: '0 auto', padding: '20px' }}>
      <h1>Dashboard</h1>
      
      <div style={{ border: '1px solid #ccc', padding: '20px', borderRadius: '8px', marginBottom: '20px' }}>
        <h2>Upload File</h2>
        <div style={{ marginBottom: '20px' }}>
          <input
            type="file"
            accept=".txt,.log"
            onChange={handleFileSelect}
            style={{ marginBottom: '10px' }}
          />
                  <p style={{ margin: '5px 0', fontSize: '14px', color: '#666' }}>
          Select a .txt or .log file to upload. Maximum size: 10MB
        </p>
        
        <p style={{ marginTop: '10px', fontSize: '13px', color: '#666' }}>
          Note: Mandatory fields to have (timestamp, src_ip, user, url, action)
        </p>
        </div>
        
        <br />
        
        <button
          onClick={handleFileUpload}
          disabled={!selectedFile || isProcessing}
          style={{
            padding: '10px 20px',
            backgroundColor: selectedFile ? '#007bff' : '#ccc',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: selectedFile && !isProcessing ? 'pointer' : 'not-allowed'
          }}
        >
          {isProcessing ? 'Processing...' : 'Upload & Analyze'}
        </button>
        
        {uploadStatus && (
          <div style={{ 
            marginTop: '10px', 
            padding: '10px', 
            backgroundColor: uploadStatus.includes('File selected') || uploadStatus.includes('successfully') || uploadStatus.includes('Processing file...') ? '#d4edda' : 
                           uploadStatus.includes('too large') ? '#fff3cd' : '#f8d7da',
            borderRadius: '4px',
            color: uploadStatus.includes('File selected') || uploadStatus.includes('successfully') || uploadStatus.includes('Processing file...') ? '#155724' : 
                   uploadStatus.includes('too large') ? '#856404' : '#721c24'
          }}>
            {uploadStatus}
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;
