// src/components/IpInputForm.tsx
import React, { useState } from 'react';
import { Form, Button, Tabs, Tab, Alert } from 'react-bootstrap';

interface IpInputFormProps {
  onScan: (singleIp: string | null, multipleIps: string[] | null, ipRanges: string[] | null) => void;
}

const IpInputForm: React.FC<IpInputFormProps> = ({ onScan }) => {
  // State for different input types
  const [singleIp, setSingleIp] = useState('');
  const [multipleIps, setMultipleIps] = useState('');
  const [ipRange, setIpRange] = useState('');
  const [activeTab, setActiveTab] = useState('single');
  const [validationError, setValidationError] = useState<string | null>(null);

  // Validate a single IP address
  const isValidIp = (ip: string): boolean => {
    const pattern = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return pattern.test(ip);
  };

  // Validate a CIDR range
  const isValidCidr = (cidr: string): boolean => {
    const pattern = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$/;
    return pattern.test(cidr);
  };

  // Validate an IP range with dash notation
  const isValidIpRange = (range: string): boolean => {
    const parts = range.split('-');
    if (parts.length !== 2) return false;
    return isValidIp(parts[0].trim()) && isValidIp(parts[1].trim());
  };

  // Handle form submission
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError(null);

    switch (activeTab) {
      case 'single':
        if (!isValidIp(singleIp)) {
          setValidationError('Please enter a valid IP address (e.g., 192.168.1.1)');
          return;
        }
        onScan(singleIp, null, null);
        break;

      case 'multiple':
        const ips = multipleIps
          .split('\n')
          .map(ip => ip.trim())
          .filter(ip => ip !== '');

        if (ips.length === 0) {
          setValidationError('Please enter at least one IP address');
          return;
        }

        const invalidIps = ips.filter(ip => !isValidIp(ip));
        if (invalidIps.length > 0) {
          setValidationError(`Invalid IP addresses: ${invalidIps.join(', ')}`);
          return;
        }

        onScan(null, ips, null);
        break;

      case 'range':
        const ranges = ipRange
          .split('\n')
          .map(range => range.trim())
          .filter(range => range !== '');

        if (ranges.length === 0) {
          setValidationError('Please enter at least one IP range');
          return;
        }

        const invalidRanges = ranges.filter(range => {
          return !isValidCidr(range) && !isValidIpRange(range);
        });

        if (invalidRanges.length > 0) {
          setValidationError(`Invalid IP ranges: ${invalidRanges.join(', ')}`);
          return;
        }

        onScan(null, null, ranges);
        break;
    }
  };

  return (
    <Form onSubmit={handleSubmit}>
      <Tabs
        activeKey={activeTab}
        onSelect={(k) => k && setActiveTab(k)}
        className="mb-3"
      >
        <Tab eventKey="single" title="Single IP">
          <Form.Group className="mb-3">
            <Form.Label>IP Address</Form.Label>
            <Form.Control
              type="text"
              placeholder="Enter IP address (e.g., 192.168.1.1)"
              value={singleIp}
              onChange={(e) => setSingleIp(e.target.value)}
            />
          </Form.Group>
        </Tab>

        <Tab eventKey="multiple" title="Multiple IPs">
          <Form.Group className="mb-3">
            <Form.Label>IP Addresses (one per line)</Form.Label>
            <Form.Control
              as="textarea"
              rows={5}
              placeholder="Enter IP addresses, one per line:
192.168.1.1
192.168.1.2
192.168.1.3"
              value={multipleIps}
              onChange={(e) => setMultipleIps(e.target.value)}
            />
          </Form.Group>
        </Tab>

        <Tab eventKey="range" title="IP Ranges">
          <Form.Group className="mb-3">
            <Form.Label>IP Ranges (one per line)</Form.Label>
            <Form.Control
              as="textarea"
              rows={5}
              placeholder="Enter IP ranges, one per line:
192.168.1.1-192.168.1.254
10.0.0.0/24"
              value={ipRange}
              onChange={(e) => setIpRange(e.target.value)}
            />
            <Form.Text className="text-muted">
              Supported formats: CIDR notation (192.168.1.0/24) or IP range (192.168.1.1-192.168.1.254)
            </Form.Text>
          </Form.Group>
        </Tab>
      </Tabs>

      {validationError && (
        <Alert variant="danger" className="mt-2">
          {validationError}
        </Alert>
      )}

      <Button variant="primary" type="submit" className="mt-2">
        Scan
      </Button>
    </Form>
  );
};

export default IpInputForm;