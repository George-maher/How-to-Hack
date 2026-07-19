import { Outlet, Link, useLocation, useNavigate } from 'react-router-dom';
import { getStoredUser, authApi, setToken, setStoredUser } from '../../services/api';

export default function Layout() {
  const location = useLocation();
  const navigate = useNavigate();
  const user = getStoredUser();

  const handleLogout = async () => {
    try {
      await authApi.logout();
    } catch {
      // ignore
    }
    setToken(null);
    setStoredUser(null);
    navigate('/login');
  };

  return (
    <div className="app-layout">
      <nav className="sidebar">
        <div className="sidebar-header">
          <h1 className="app-title">HowToHack</h1>
          <p className="app-subtitle">Security Scanner</p>
        </div>
        {user && (
          <div className="sidebar-user">
            <span className="user-name">{user.name}</span>
            <span className="user-email">{user.email}</span>
          </div>
        )}
        <ul className="nav-list">
          <li>
            <Link
              to="/"
              className={`nav-link ${location.pathname === '/' ? 'active' : ''}`}
            >
              Dashboard
            </Link>
          </li>
          <li>
            <Link
              to="/projects/new"
              className={`nav-link ${location.pathname === '/projects/new' ? 'active' : ''}`}
            >
              New Project
            </Link>
          </li>
          <li>
            <Link
              to="/reports"
              className={`nav-link ${location.pathname.startsWith('/reports') ? 'active' : ''}`}
            >
              Reports
            </Link>
          </li>
        </ul>
        <div className="sidebar-footer">
          <button onClick={handleLogout} className="btn-logout">
            Logout
          </button>
        </div>
      </nav>
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}
