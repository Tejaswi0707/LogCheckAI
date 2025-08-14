
import { Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

const Navigation = () => {
  const { isAuthenticated, user, logout } = useAuth();

  return (
    <nav style={{
      backgroundColor: '#f8f9fa',
      padding: '15px',
      marginBottom: '20px',
      borderBottom: '1px solid #dee2e6'
    }}>
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        maxWidth: '1200px',
        margin: '0 auto'
      }}>
        <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
          <Link to="/dashboard" style={{
            textDecoration: 'none',
            color: '#333',
            fontWeight: 'bold',
            fontSize: '18px'
          }}>
            LogCheckAI
          </Link>
        </div>

        <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
          {isAuthenticated ? (
            <>
              <span style={{ color: '#666', fontSize: '14px' }}>
                Welcome, {user?.email}
              </span>
              <button
                onClick={logout}
                style={{
                  padding: '8px 16px',
                  backgroundColor: '#dc3545',
                  color: 'white',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: 'pointer',
                  fontSize: '14px'
                }}
              >
                Logout
              </button>
            </>
          ) : null}
        </div>
      </div>
    </nav>
  );
};

export default Navigation;
