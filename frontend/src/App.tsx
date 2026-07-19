import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { getStoredUser } from './services/api';
import Layout from './components/layout/Layout';
import Dashboard from './pages/Dashboard';
import ProjectDetail from './pages/ProjectDetail';
import ReportDetail from './pages/ReportDetail';
import Reports from './pages/Reports';
import ScanDetail from './pages/ScanDetail';
import CreateProject from './pages/CreateProject';
import Login from './pages/Login';
import Register from './pages/Register';
import ErrorBoundary from './components/ErrorBoundary';
import './App.css';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const user = getStoredUser();
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}

function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route
            element={
              <ProtectedRoute>
                <Layout />
              </ProtectedRoute>
            }
          >
            <Route path="/" element={<Dashboard />} />
            <Route path="/projects/new" element={<CreateProject />} />
            <Route path="/projects/:id" element={<ProjectDetail />} />
            <Route path="/scans/:id" element={<ScanDetail />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/reports/:id" element={<ReportDetail />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ErrorBoundary>
  );
}

export default App;
