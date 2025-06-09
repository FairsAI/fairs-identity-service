/**
 * Secure Cookies Utility
 * 
 * Provides enhanced cookie security with modern security attributes
 * and protection mechanisms for handling cookies.
 */

const isProduction = process.env.NODE_ENV === 'production';

/**
 * Set a secure cookie with modern security attributes
 * 
 * @param {string} name - Cookie name
 * @param {string} value - Cookie value
 * @param {Object} options - Cookie options
 * @param {number} [options.maxAge=31536000] - Cookie max age in seconds (default: 1 year)
 * @param {string} [options.path='/'] - Cookie path
 * @param {string} [options.domain] - Cookie domain
 * @param {boolean} [options.secure] - Whether to use Secure attribute (default: true in production)
 * @param {string} [options.sameSite='Lax'] - SameSite attribute (Strict, Lax, or None)
 * @param {boolean} [options.useSecurePrefix=true] - Whether to use __Secure- prefix in production
 */
function setSecureCookie(name, value, options = {}) {
  const secure = options.secure ?? isProduction;
  const sameSite = options.sameSite || 'Lax';
  const maxAge = options.maxAge || 31536000; // Default 1 year
  const path = options.path || '/';
  
  // Use __Secure- prefix in production with HTTPS to improve security
  // This ensures the cookie is only sent over HTTPS connections
  const useSecurePrefix = options.useSecurePrefix ?? isProduction;
  const cookieName = (secure && useSecurePrefix) ? `__Secure-${name}` : name;
  
  let cookieString = `${cookieName}=${encodeURIComponent(value)}; path=${path}; max-age=${maxAge}; SameSite=${sameSite}`;
  
  if (secure) {
    cookieString += '; Secure';
  }
  
  if (options.domain) {
    cookieString += `; Domain=${options.domain}`;
  }
  
  try {
    document.cookie = cookieString;
    return true;
  } catch (error) {
    console.error(`[Secure Cookies] Error setting cookie ${name}:`, error);
    return false;
  }
}

/**
 * Get a cookie value, checking for secure prefix if necessary
 * 
 * @param {string} name - Cookie name
 * @param {Object} options - Cookie options
 * @param {boolean} [options.checkSecurePrefix=true] - Whether to check for __Secure- prefix
 * @returns {string|null} - Cookie value or null if not found
 */
function getSecureCookie(name, options = {}) {
  const checkSecurePrefix = options.checkSecurePrefix ?? isProduction;
  
  // Try with normal name first
  let value = getCookieValue(name);
  
  // If not found and should check secure prefix, try with __Secure- prefix
  if (value === null && checkSecurePrefix) {
    value = getCookieValue(`__Secure-${name}`);
  }
  
  return value;
}

/**
 * Remove a cookie
 * 
 * @param {string} name - Cookie name
 * @param {Object} options - Cookie options
 * @param {string} [options.path='/'] - Cookie path
 * @param {string} [options.domain] - Cookie domain
 * @param {boolean} [options.secure] - Whether cookie was secure
 * @param {boolean} [options.checkSecurePrefix=true] - Whether to check for __Secure- prefix
 */
function removeSecureCookie(name, options = {}) {
  const path = options.path || '/';
  const secure = options.secure ?? isProduction;
  const checkSecurePrefix = options.checkSecurePrefix ?? isProduction;
  
  // Options for expiring the cookie
  const expireOptions = {
    maxAge: 0, // Expire immediately
    path,
    domain: options.domain,
    secure,
    sameSite: 'Lax',
    useSecurePrefix: false // Don't add prefix here, we'll handle it manually
  };
  
  // Remove regular cookie
  setSecureCookie(name, '', expireOptions);
  
  // Remove secure prefixed cookie if needed
  if (checkSecurePrefix) {
    setSecureCookie(`__Secure-${name}`, '', expireOptions);
  }
}

/**
 * Get cookie value helper function
 * 
 * @param {string} name - Exact cookie name
 * @returns {string|null} - Cookie value or null if not found
 * @private
 */
function getCookieValue(name) {
  try {
    const match = document.cookie.match(new RegExp(
      '(^|;\\s*)' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=([^;]*)'
    ));
    
    return match ? decodeURIComponent(match[2]) : null;
  } catch (error) {
    console.error(`[Secure Cookies] Error getting cookie ${name}:`, error);
    return null;
  }
}

/**
 * Check if cookies are enabled in the browser
 * 
 * @returns {boolean} - Whether cookies are enabled
 */
function areCookiesEnabled() {
  try {
    // Try to set a test cookie
    const testCookie = 'testcookie';
    document.cookie = `${testCookie}=1; path=/; max-age=10`;
    
    // Check if the test cookie was set
    const cookieEnabled = document.cookie.indexOf(testCookie) !== -1;
    
    // Clean up the test cookie
    document.cookie = `${testCookie}=; path=/; max-age=0`;
    
    return cookieEnabled;
  } catch (error) {
    // An error likely means cookies are disabled
    return false;
  }
}

module.exports = {
  setSecureCookie,
  getSecureCookie,
  removeSecureCookie,
  areCookiesEnabled
}; 