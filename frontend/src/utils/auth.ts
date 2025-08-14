// JWT Token Management Utilities

export interface User {
  id: number;
  email: string;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

/**
 * Store authentication data in localStorage
 */
export const storeAuthData = (tokens: AuthTokens, user: User) => {
  try {
    // Store tokens
    localStorage.setItem('access_token', tokens.access_token);
    localStorage.setItem('refresh_token', tokens.refresh_token);
    
    // Store user info
    localStorage.setItem('user', JSON.stringify(user));
    
    // Store token expiration
    const expiresAt = Date.now() + (tokens.expires_in * 1000);
    localStorage.setItem('token_expires_at', expiresAt.toString());
    
    console.log('✅ Authentication data stored successfully');
    return true;
  } catch (error) {
    console.error('❌ Error storing authentication data:', error);
    return false;
  }
};

/**
 * Get the current access token from localStorage
 */
export const getAccessToken = (): string | null => {
  return localStorage.getItem('access_token');
};

/**
 * Get the current refresh token from localStorage
 */
export const getRefreshToken = (): string | null => {
  return localStorage.getItem('refresh_token');
};

/**
 * Get the current user from localStorage
 */
export const getCurrentUser = (): User | null => {
  try {
    const userStr = localStorage.getItem('user');
    return userStr ? JSON.parse(userStr) : null;
  } catch (error) {
    console.error('❌ Error parsing user data:', error);
    return null;
  }
};

/**
 * Check if the user is currently authenticated
 */
export const isAuthenticated = (): boolean => {
  const token = getAccessToken();
  if (!token) return false;
  
  // Check if token has expired
  const expiresAt = localStorage.getItem('token_expires_at');
  if (expiresAt) {
    const expirationTime = parseInt(expiresAt);
    if (Date.now() >= expirationTime) {
      // Token has expired, clear it
      clearAuthData();
      return false;
    }
  }
  
  return true;
};

/**
 * Check if the access token has expired
 */
export const isTokenExpired = (): boolean => {
  const expiresAt = localStorage.getItem('token_expires_at');
  if (!expiresAt) return true;
  
  const expirationTime = parseInt(expiresAt);
  return Date.now() >= expirationTime;
};

/**
 * Get the time until token expiration in milliseconds
 */
export const getTimeUntilExpiration = (): number => {
  const expiresAt = localStorage.getItem('token_expires_at');
  if (!expiresAt) return 0;
  
  const expirationTime = parseInt(expiresAt);
  return Math.max(0, expirationTime - Date.now());
};

/**
 * Clear all authentication data from localStorage
 */
export const clearAuthData = (): void => {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  localStorage.removeItem('user');
  localStorage.removeItem('token_expires_at');
  console.log('✅ Authentication data cleared');
};

/**
 * Create Authorization header with Bearer token
 */
export const getAuthHeader = (): { Authorization: string } | {} => {
  const token = getAccessToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
};

/**
 * Logout user and redirect to login
 */
export const logout = (): void => {
  clearAuthData();
  // Redirect to login page
  window.location.href = '/login';
};

/**
 * Refresh the access token using the refresh token
 */
export const refreshAccessToken = async (): Promise<boolean> => {
  try {
    const refreshToken = getRefreshToken();
    if (!refreshToken) {
      console.log('❌ No refresh token available');
      return false;
    }

    const response = await fetch('http://localhost:5000/refresh', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${refreshToken}`
      }
    });

    if (response.ok) {
      const data = await response.json();
      
      // Store new access token
      if (data.access_token) {
        localStorage.setItem('access_token', data.access_token);
        
        // Update expiration
        if (data.expires_in) {
          const expiresAt = Date.now() + (data.expires_in * 1000);
          localStorage.setItem('token_expires_at', expiresAt.toString());
        }
        
        console.log('✅ Access token refreshed successfully');
        return true;
      }
    } else {
      console.log('❌ Failed to refresh access token');
      // If refresh fails, clear auth data
      clearAuthData();
    }
    
    return false;
  } catch (error) {
    console.error('❌ Error refreshing access token:', error);
    clearAuthData();
    return false;
  }
};

