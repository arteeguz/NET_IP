// src/components/ScannerForm.tsx
import React, { useState } from 'react';
import { Form, Button, Card, Spinner, Alert } from 'react-bootstrap';
import axios from 'axios';

// Define the shape of scan results from API
interface ScanResult {
  ipAddress: string;
  hostname: string;
  ramSize: string;
  status: string;
  errorMessage?: string;
}

const ScannerForm: React.FC = () => {
  // State management
  const [ipAddress, setIpAddress] = useState('');
  const [scanResults, setScanResults] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Handle form submission
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    
    try {
      // Call the API to scan the machine
      // Note: Adjust the port to match your .NET app
      const response = await axios.post(
        'http://localhost:5023/api/scanner/scan',
        { ipAddress }
        // No auth object needed since we removed authentication
      );
      
      setScanResults(response.data);
    } catch (err: any) {
      console.error('Error scanning:', err);
      setError(err.response?.data || 'Failed to scan machine. Check console for details.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="mt-4">
      <Card.Header as="h5">Network Scanner</Card.Header>
      <Card.Body>
        {/* IP Input Form */}
        <Form onSubmit={handleSubmit}>
          <Form.Group className="mb-3">
            <Form.Label>IP Address</Form.Label>
            <Form.Control
              type="text"
              placeholder="Enter IP address to scan"
              value={ipAddress}
              onChange={(e) => setIpAddress(e.target.value)}
              required
            />
          </Form.Group>
          
          <Button variant="primary" type="submit" disabled={loading}>
            {loading ? (
              <>
                <Spinner as="span" animation="border" size="sm" role="status" aria-hidden="true" />
                {' '}Scanning...
              </>
            ) : (
              'Scan Machine'
            )}
          </Button>
        </Form>
        
        {/* Error Display */}
        {error && (
          <Alert variant="danger" className="mt-3">
            {error}
          </Alert>
        )}
        
        {/* Results Display */}
        {scanResults && !error && (
          <div className="mt-4">
            <h5>Scan Results</h5>
            <table className="table table-bordered">
              <thead>
                <tr>
                  <th>Property</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>IP Address</td>
                  <td>{scanResults.ipAddress}</td>
                </tr>
                <tr>
                  <td>Hostname</td>
                  <td>{scanResults.hostname}</td>
                </tr>
                <tr>
                  <td>RAM Size</td>
                  <td>{scanResults.ramSize}</td>
                </tr>
                <tr>
                  <td>Status</td>
                  <td>{scanResults.status}</td>
                </tr>
              </tbody>
            </table>
          </div>
        )}
      </Card.Body>
    </Card>
  );
};

export default ScannerForm;