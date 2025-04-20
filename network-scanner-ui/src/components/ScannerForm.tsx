// src/components/ScannerForm.tsx
import React, { useState } from 'react';
import { Card, Alert, Spinner, Modal, Button } from 'react-bootstrap';
import axios from 'axios';
import IpInputForm from './IpInputForm';
import ScanResultsGrid from './ScanResultsGrid';
import ScanResultDetail from './ScanResultDetail'; // We'll create this next

// Define the shape of scan results from API
interface ScanResult {
  ipAddress: string;
  hostname: string;
  ramSize: string;
  windowsVersion: string;
  windowsRelease: string;
  officeVersion: string;
  machineType: string;
  machineSku: string;
  lastLoggedUser: string;
  cpuInfo: string;
  gpuInfo: string;
  diskSize: string;
  diskFreeSpace: string;
  biosVersion: string;
  macAddress: string;
  openPorts: number[];
  status: string;
  errorMessage?: string;
}

interface BatchScanResponse {
  totalIps: number;
  scannedIps: number;
  successfulScans: number;
  failedScans: number;
  results: ScanResult[];
}

const ScannerForm: React.FC = () => {
  // State for scan results and UI
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedResult, setSelectedResult] = useState<ScanResult | null>(null);
  const [showDetailModal, setShowDetailModal] = useState(false);
  
  // State for batch scan progress
  const [progress, setProgress] = useState<{
    total: number;
    scanned: number;
    successful: number;
    failed: number;
  } | undefined>(undefined);

  // API base URL (from environment or default)
  const API_BASE_URL = 'http://localhost:5023';

  // Handle scanning (single IP, multiple IPs, or IP ranges)
  const handleScan = async (singleIp: string | null, multipleIps: string[] | null, ipRanges: string[] | null) => {
    setLoading(true);
    setError(null);
    setScanResults([]);
    setProgress(undefined);
    
    try {
      if (singleIp) {
        // Single IP scan
        const response = await axios.post(
          `${API_BASE_URL}/api/scanner/scan`, 
          { ipAddress: singleIp }
        );
        
        setScanResults([response.data]);
      } else {
        // Batch scan
        const response = await axios.post(
          `${API_BASE_URL}/api/scanner/batch-scan`, 
          { 
            ipAddresses: multipleIps, 
            ipRanges: ipRanges 
          }
        );
        
        const batchResponse = response.data as BatchScanResponse;
        setScanResults(batchResponse.results);
        setProgress({
          total: batchResponse.totalIps,
          scanned: batchResponse.scannedIps,
          successful: batchResponse.successfulScans,
          failed: batchResponse.failedScans
        });
      }
    } catch (err: any) {
      console.error('Error scanning:', err);
      setError(err.response?.data || 'Failed to scan. Check console for details.');
    } finally {
      setLoading(false);
    }
  };

  // Show detail modal for a selected result
  const showDetails = (result: ScanResult) => {
    setSelectedResult(result);
    setShowDetailModal(true);
  };

  return (
    <Card className="mt-4">
      <Card.Header as="h5">Network Scanner</Card.Header>
      <Card.Body>
        {/* IP Input Form */}
        <IpInputForm onScan={handleScan} />
        
        {/* Error Display */}
        {error && (
          <Alert variant="danger" className="mt-3">
            {error}
          </Alert>
        )}
        
        {/* Loading Indicator */}
        {loading && (
          <div className="text-center mt-4">
            <Spinner animation="border" role="status">
              <span className="visually-hidden">Loading...</span>
            </Spinner>
            <p className="mt-2">Scanning in progress...</p>
          </div>
        )}
        
        {/* Results Grid */}
        {(scanResults.length > 0 || loading) && (
          <div className="mt-4">
            <h5>Scan Results</h5>
            <ScanResultsGrid 
              results={scanResults} 
              loading={loading} 
              progress={progress}
              onViewDetails={showDetails}
            />
          </div>
        )}
        
        {/* Detail Modal */}
        <Modal 
          show={showDetailModal} 
          onHide={() => setShowDetailModal(false)}
          size="lg"
        >
          <Modal.Header closeButton>
            <Modal.Title>
              Scan Details: {selectedResult?.ipAddress} {selectedResult?.hostname && `(${selectedResult.hostname})`}
            </Modal.Title>
          </Modal.Header>
          <Modal.Body>
            {selectedResult && <ScanResultDetail result={selectedResult} />}
          </Modal.Body>
          <Modal.Footer>
            <Button variant="secondary" onClick={() => setShowDetailModal(false)}>
              Close
            </Button>
          </Modal.Footer>
        </Modal>
      </Card.Body>
    </Card>
  );
};

export default ScannerForm;