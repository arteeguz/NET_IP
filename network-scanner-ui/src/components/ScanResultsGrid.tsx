// src/components/ScanResultsGrid.tsx
import React, { useState } from 'react';
import { Table, Form, InputGroup, Button, Badge } from 'react-bootstrap';

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

interface ScanResultsGridProps {
  results: ScanResult[];
  loading: boolean;
  progress?: {
    total: number;
    scanned: number;
    successful: number;
    failed: number;
  };
  onViewDetails: (result: ScanResult) => void; // Add this prop to fix the error
}

const ScanResultsGrid: React.FC<ScanResultsGridProps> = ({ results, loading, progress, onViewDetails }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [sortField, setSortField] = useState<keyof ScanResult>('ipAddress');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');
  
  // Handle sorting
  const handleSort = (field: keyof ScanResult) => {
    if (field === sortField) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };
  
  // Filter and sort results
  const filteredResults = results
    .filter(result => {
      if (!searchTerm) return true;
      const searchLower = searchTerm.toLowerCase();
      
      // Search in multiple fields
      return (
        result.ipAddress.toLowerCase().includes(searchLower) ||
        (result.hostname?.toLowerCase() || '').includes(searchLower) ||
        (result.machineType?.toLowerCase() || '').includes(searchLower) ||
        (result.machineSku?.toLowerCase() || '').includes(searchLower) ||
        (result.windowsVersion?.toLowerCase() || '').includes(searchLower) ||
        (result.status?.toLowerCase() || '').includes(searchLower)
      );
    })
    .sort((a, b) => {
      const aValue = a[sortField] as string || '';
      const bValue = b[sortField] as string || '';
      
      const comparison = aValue.localeCompare(bValue);
      return sortDirection === 'asc' ? comparison : -comparison;
    });
  
  return (
    <div>
      {/* Progress information */}
      {progress && (
        <div className="d-flex justify-content-between mb-3">
          <div>
            <strong>Progress:</strong> {progress.scanned} / {progress.total} ({Math.round((progress.scanned / progress.total) * 100)}%)
          </div>
          <div>
            <Badge bg="success" className="me-2">Success: {progress.successful}</Badge>
            <Badge bg="danger">Failed: {progress.failed}</Badge>
          </div>
        </div>
      )}
      
      {/* Search and filter */}
      <InputGroup className="mb-3">
        <InputGroup.Text>
          <i className="bi bi-search"></i>
        </InputGroup.Text>
        <Form.Control
          placeholder="Search in results..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
        <Button variant="outline-secondary" onClick={() => setSearchTerm('')}>
          Clear
        </Button>
      </InputGroup>
      
      {/* Results table */}
      <Table striped bordered hover responsive>
        <thead>
          <tr>
            <th onClick={() => handleSort('ipAddress')} className="sortable">
              IP Address {sortField === 'ipAddress' && (sortDirection === 'asc' ? '▲' : '▼')}
            </th>
            <th onClick={() => handleSort('hostname')} className="sortable">
              Hostname {sortField === 'hostname' && (sortDirection === 'asc' ? '▲' : '▼')}
            </th>
            <th onClick={() => handleSort('machineType')} className="sortable">
              Manufacturer {sortField === 'machineType' && (sortDirection === 'asc' ? '▲' : '▼')}
            </th>
            <th onClick={() => handleSort('machineSku')} className="sortable">
              Model {sortField === 'machineSku' && (sortDirection === 'asc' ? '▲' : '▼')}
            </th>
            <th onClick={() => handleSort('ramSize')} className="sortable">
              RAM {sortField === 'ramSize' && (sortDirection === 'asc' ? '▲' : '▼')}
            </th>
            <th onClick={() => handleSort('windowsVersion')} className="sortable">
              Windows {sortField === 'windowsVersion' && (sortDirection === 'asc' ? '▲' : '▼')}
            </th>
            <th onClick={() => handleSort('status')} className="sortable">
              Status {sortField === 'status' && (sortDirection === 'asc' ? '▲' : '▼')}
            </th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {loading && filteredResults.length === 0 ? (
            <tr>
              <td colSpan={8} className="text-center">Loading...</td>
            </tr>
          ) : filteredResults.length === 0 ? (
            <tr>
              <td colSpan={8} className="text-center">No results found</td>
            </tr>
          ) : (
            filteredResults.map((result, index) => (
              <tr key={index}>
                <td>{result.ipAddress}</td>
                <td>{result.hostname || 'N/A'}</td>
                <td>{result.machineType || 'N/A'}</td>
                <td>{result.machineSku || 'N/A'}</td>
                <td>{result.ramSize || 'N/A'}</td>
                <td>
                  {result.windowsVersion} {result.windowsRelease && `(${result.windowsRelease})`}
                </td>
                <td>
                  <Badge bg={result.status === 'success' ? 'success' : 'danger'}>
                    {result.status}
                  </Badge>
                </td>
                <td>
                  <Button size="sm" variant="info" onClick={() => onViewDetails(result)}>
                    Details
                  </Button>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </Table>
      
      {/* Replace styled-jsx with standard CSS */}
      <style>
        {`
          .sortable {
            cursor: pointer;
          }
          .sortable:hover {
            background-color: #f8f9fa;
          }
        `}
      </style>
    </div>
  );
};

export default ScanResultsGrid;