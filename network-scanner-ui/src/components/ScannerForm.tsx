// src/components/ScannerForm.tsx
import React, { useState } from 'react';
import { Form, Button, Card, Spinner, Alert, Badge, Accordion } from 'react-bootstrap';
import axios from 'axios';

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
            <h5>Scan Results for {scanResults.ipAddress}</h5>
            <Accordion defaultActiveKey="0">
              <Accordion.Item eventKey="0">
                <Accordion.Header>Basic Information</Accordion.Header>
                <Accordion.Body>
                  <table className="table table-bordered">
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
                        <td>Last Logged User</td>
                        <td>{scanResults.lastLoggedUser}</td>
                      </tr>
                      <tr>
                        <td>Machine Manufacturer</td>
                        <td>{scanResults.machineType}</td>
                      </tr>
                      <tr>
                        <td>Machine Model</td>
                        <td>{scanResults.machineSku}</td>
                      </tr>
                      <tr>
                        <td>Status</td>
                        <td>{scanResults.status}</td>
                      </tr>
                    </tbody>
                  </table>
                </Accordion.Body>
              </Accordion.Item>
              
              <Accordion.Item eventKey="1">
                <Accordion.Header>System Information</Accordion.Header>
                <Accordion.Body>
                  <table className="table table-bordered">
                    <tbody>
                      <tr>
                        <td>Windows Version</td>
                        <td>{scanResults.windowsVersion}</td>
                      </tr>
                      <tr>
                        <td>Windows Release</td>
                        <td>{scanResults.windowsRelease}</td>
                      </tr>
                      <tr>
                        <td>Microsoft Office Version</td>
                        <td>{scanResults.officeVersion}</td>
                      </tr>
                      <tr>
                        <td>BIOS Version</td>
                        <td>{scanResults.biosVersion}</td>
                      </tr>
                    </tbody>
                  </table>
                </Accordion.Body>
              </Accordion.Item>
              
              <Accordion.Item eventKey="2">
                <Accordion.Header>Hardware Information</Accordion.Header>
                <Accordion.Body>
                  <table className="table table-bordered">
                    <tbody>
                      <tr>
                        <td>CPU</td>
                        <td>{scanResults.cpuInfo}</td>
                      </tr>
                      <tr>
                        <td>RAM</td>
                        <td>{scanResults.ramSize}</td>
                      </tr>
                      <tr>
                        <td>GPU</td>
                        <td>{scanResults.gpuInfo}</td>
                      </tr>
                      <tr>
                        <td>Disk Size</td>
                        <td>{scanResults.diskSize}</td>
                      </tr>
                      <tr>
                        <td>Disk Free Space</td>
                        <td>{scanResults.diskFreeSpace}</td>
                      </tr>
                    </tbody>
                  </table>
                </Accordion.Body>
              </Accordion.Item>
              
              <Accordion.Item eventKey="3">
                <Accordion.Header>Network Information</Accordion.Header>
                <Accordion.Body>
                  <table className="table table-bordered">
                    <tbody>
                      <tr>
                        <td>MAC Address</td>
                        <td>{scanResults.macAddress}</td>
                      </tr>
                      <tr>
                        <td>Open Ports</td>
                        <td>
                          {scanResults.openPorts && scanResults.openPorts.length > 0 ? (
                            <div>
                              {scanResults.openPorts.map(port => (
                                <Badge bg="info" className="me-1" key={port}>{port}</Badge>
                              ))}
                            </div>
                          ) : (
                            "No open ports detected"
                          )}
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </Accordion.Body>
              </Accordion.Item>
            </Accordion>
          </div>
        )}
      </Card.Body>
    </Card>
  );
};

export default ScannerForm;