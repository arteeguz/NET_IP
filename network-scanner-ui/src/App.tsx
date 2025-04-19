// src/App.tsx
import React from 'react';
import { Container, Row, Col, Navbar } from 'react-bootstrap';
import ScannerForm from './components/ScannerForm';
import 'bootstrap/dist/css/bootstrap.min.css';

function App() {
  return (
    <div className="App">
      {/* Navigation Bar */}
      <Navbar bg="dark" variant="dark">
        <Container>
          <Navbar.Brand>Network Scanner</Navbar.Brand>
        </Container>
      </Navbar>
      
      {/* Main Content */}
      <Container>
        <Row className="justify-content-md-center">
          <Col md={8}>
            <ScannerForm />
          </Col>
        </Row>
      </Container>
    </div>
  );
}

export default App;