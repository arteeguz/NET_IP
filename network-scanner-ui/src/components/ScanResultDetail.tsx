// src/components/ScanResultDetail.tsx
import React from 'react';
import { Accordion, Table, Badge } from 'react-bootstrap';

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

interface ScanResultDetailProps {
  result: ScanResult;
}

const ScanResultDetail: React.FC<ScanResultDetailProps> = ({ result }) => {
  return (
    <Accordion defaultActiveKey="0">
      <Accordion.Item eventKey="0">
        <Accordion.Header>Basic Information</Accordion.Header>
        <Accordion.Body>
          <Table bordered>
            <tbody>
              <tr>
                <td width="30%"><strong>IP Address</strong></td>
                <td>{result.ipAddress}</td>
              </tr>
              <tr>
                <td><strong>Hostname</strong></td>
                <td>{result.hostname || 'N/A'}</td>
              </tr>
              <tr>
                <td><strong>Last Logged User</strong></td>
                <td>{result.lastLoggedUser || 'N/A'}</td>
              </tr>
              <tr>
                <td><strong>Machine Manufacturer</strong></td>
                <td>{result.machineType || 'N/A'}</td>
              </tr>
              <tr>
                <td><strong>Machine Model</strong></td>
                <td>{result.machineSku || 'N/A'}</td>
              </tr>
              <tr>
                <td><strong>Status</strong></td>
                <td>
                  <Badge bg={result.status === 'success' ? 'success' : 'danger'}>
                    {result.status}
                  </Badge>
                  {result.errorMessage && ` - ${result.errorMessage}`}
                </td>
              </tr>
            </tbody>
          </Table>
        </Accordion.Body>
      </Accordion.Item>
      
      <Accordion.Item eventKey="1">
        <Accordion.Header>System Information</Accordion.Header>
        <Accordion.Body>
          <Table bordered>
            <tbody>
              <tr>
                <td width="30%"><strong>Windows Version</strong></td>
                <td>{result.windowsVersion || 'N/A'}</td>
              </tr>
              <tr>
                <td><strong>Windows Release</strong></td>
                <td>{result.windowsRelease || 'N/A'}</td>
              </tr>
              <tr>
                <td><strong>Microsoft Office Version</strong></td>
                <td>{result.officeVersion || 'N/A'}</td>
              </tr>
              <tr>
                <td><strong>BIOS Version</strong></td>
                <td>{result.biosVersion || 'N/A'}</td>
              </tr>
            </tbody>
          </Table>
        </Accordion.Body>
      </Accordion.Item>
      
      <Accordion.Item eventKey="2">
        <Accordion.Header>Hardware Information</Accordion.Header>
        <Accordion.Body>
          <Table bordered>
            <tbody>
              <tr>
                <td width="30%"><strong>CPU</strong></td>
                <td>{result.cpuInfo || 'N/A'}</td>
              </tr>
              <tr>
                <td><strong>RAM</strong></td>
                <td>{result.ramSize || 'N/A'}</td>
              </tr>
              <tr>
                <td><strong>GPU</strong></td>
                <td>{result.gpuInfo || 'N/A'}</td>
              </tr>
              <tr>
                <td><strong>Disk Size</strong></td>
                <td>{result.diskSize || 'N/A'}</td>
              </tr>
              <tr>
                <td><strong>Disk Free Space</strong></td>
                <td>{result.diskFreeSpace || 'N/A'}</td>
              </tr>
            </tbody>
          </Table>
        </Accordion.Body>
      </Accordion.Item>
      
      <Accordion.Item eventKey="3">
        <Accordion.Header>Network Information</Accordion.Header>
        <Accordion.Body>
          <Table bordered>
            <tbody>
              <tr>
                <td width="30%"><strong>MAC Address</strong></td>
                <td>{result.macAddress || 'N/A'}</td>
              </tr>
              <tr>
                <td><strong>Open Ports</strong></td>
                <td>
                  {result.openPorts && result.openPorts.length > 0 ? (
                    <div>
                      {result.openPorts.map(port => (
                        <Badge bg="info" className="me-1" key={port}>{port}</Badge>
                      ))}
                    </div>
                  ) : (
                    "No open ports detected"
                  )}
                </td>
              </tr>
            </tbody>
          </Table>
        </Accordion.Body>
      </Accordion.Item>
    </Accordion>
  );
};

export default ScanResultDetail;