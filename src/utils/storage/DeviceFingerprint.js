/**
 * Device Fingerprint Generator
 * 
 * Creates a privacy-respecting device fingerprint for key derivation.
 * This uses multiple signals without collecting excessive identifiable information.
 */

class DeviceFingerprint {
  /**
   * Generates a device fingerprint using available browser features
   * 
   * @async
   * @param {Object} [options] - Configuration options
   * @param {boolean} [options.useNavigator=true] - Whether to use navigator properties
   * @param {boolean} [options.useScreen=true] - Whether to use screen properties
   * @param {boolean} [options.useCanvas=false] - Whether to use canvas fingerprinting
   * @param {boolean} [options.useWebGL=false] - Whether to use WebGL fingerprinting
   * @param {boolean} [options.useFonts=false] - Whether to use font detection
   * @param {Array<string>} [options.fontList] - List of fonts to check
   * @returns {Promise<string>} A stable fingerprint hash
   */
  async generateFingerprint(options = {}) {
    const defaultOptions = {
      useNavigator: true,
      useScreen: true,
      useCanvas: false,
      useWebGL: false,
      useFonts: false,
      fontList: []
    };

    const config = { ...defaultOptions, ...options };
    const components = [];

    // Collect navigator properties (platform, userAgent subset, language)
    if (config.useNavigator && navigator) {
      // Use limited properties to respect privacy
      const navigatorData = {
        platform: navigator.platform || '',
        language: navigator.language || '',
        // Use only browser family and OS, not the full user agent
        browserFamily: this._getBrowserFamily(),
        osFamily: this._getOSFamily()
      };
      components.push(JSON.stringify(navigatorData));
    }

    // Collect screen properties
    if (config.useScreen && window.screen) {
      const screenData = {
        width: window.screen.width,
        height: window.screen.height,
        colorDepth: window.screen.colorDepth,
        pixelRatio: window.devicePixelRatio || 1
      };
      components.push(JSON.stringify(screenData));
    }

    // Use canvas fingerprinting if enabled
    // This is more aggressive fingerprinting, so it's off by default
    if (config.useCanvas) {
      const canvasFingerprint = this._getCanvasFingerprint();
      if (canvasFingerprint) {
        components.push(canvasFingerprint);
      }
    }

    // Use WebGL fingerprinting if enabled
    // This is more aggressive fingerprinting, so it's off by default
    if (config.useWebGL) {
      const webglFingerprint = this._getWebGLFingerprint();
      if (webglFingerprint) {
        components.push(webglFingerprint);
      }
    }

    // Check for installed fonts if enabled
    if (config.useFonts && config.fontList && config.fontList.length > 0) {
      const fontFingerprint = this._getFontFingerprint(config.fontList);
      components.push(fontFingerprint);
    }

    // Add timezone information
    components.push(String(new Date().getTimezoneOffset()));

    // Add basic feature detection
    components.push(this._getFeatureDetection());
    
    // Join all components and hash them
    return await this._hashFingerprint(components.join('|'));
  }

  /**
   * Hashes the fingerprint components using SHA-256 if available
   * 
   * @private
   * @async
   * @param {string} fingerprint - The fingerprint string to hash
   * @returns {Promise<string>} - The hashed fingerprint
   */
  async _hashFingerprint(fingerprint) {
    try {
      // Use Web Crypto API if available
      if (window.crypto && window.crypto.subtle && window.crypto.subtle.digest) {
        const encoder = new TextEncoder();
        const data = encoder.encode(fingerprint);
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
      }
    } catch (e) {
      console.warn('Web Crypto API unavailable for fingerprint hashing, using fallback');
    }

    // Fallback to simple hashing
    return this._simpleHash(fingerprint);
  }

  /**
   * A simple fallback hash function
   * 
   * @private
   * @param {string} str - The string to hash
   * @returns {string} - A simple hash of the input
   */
  _simpleHash(str) {
    let hash = 0;
    if (str.length === 0) return hash.toString(16);
    
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    
    // Convert to hex string and ensure positive
    return (hash >>> 0).toString(16);
  }

  /**
   * Extract browser family from user agent
   * 
   * @private
   * @returns {string} The browser family
   */
  _getBrowserFamily() {
    const ua = navigator.userAgent;
    
    if (ua.includes('Firefox')) return 'Firefox';
    if (ua.includes('Chrome') && !ua.includes('Edg')) return 'Chrome';
    if (ua.includes('Safari') && !ua.includes('Chrome')) return 'Safari';
    if (ua.includes('Edg')) return 'Edge';
    if (ua.includes('Trident') || ua.includes('MSIE')) return 'IE';
    if (ua.includes('Opera') || ua.includes('OPR')) return 'Opera';
    
    return 'Other';
  }

  /**
   * Extract OS family from user agent
   * 
   * @private
   * @returns {string} The OS family
   */
  _getOSFamily() {
    const ua = navigator.userAgent;
    
    if (ua.includes('Windows')) return 'Windows';
    if (ua.includes('Mac')) return 'Mac';
    if (ua.includes('Linux')) return 'Linux';
    if (ua.includes('Android')) return 'Android';
    if (ua.includes('iOS') || ua.includes('iPhone') || ua.includes('iPad')) return 'iOS';
    
    return 'Other';
  }

  /**
   * Get feature detection fingerprint
   * 
   * @private
   * @returns {string} Feature detection string
   */
  _getFeatureDetection() {
    const features = {
      localStorage: !!window.localStorage,
      sessionStorage: !!window.sessionStorage,
      indexedDB: !!window.indexedDB,
      webWorker: !!window.Worker,
      webCrypto: !!(window.crypto && window.crypto.subtle),
      serviceWorker: 'serviceWorker' in navigator,
      touch: 'ontouchstart' in window
    };
    
    return JSON.stringify(features);
  }

  /**
   * Create a canvas fingerprint
   * 
   * @private
   * @returns {string|null} Canvas fingerprint or null
   */
  _getCanvasFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      
      if (!ctx) return null;
      
      // Set canvas size
      canvas.width = 200;
      canvas.height = 50;
      
      // Text with different styles and colors
      ctx.textBaseline = 'top';
      ctx.font = '16px Arial';
      ctx.fillStyle = '#F60';
      ctx.fillRect(125, 10, 50, 30);
      ctx.fillStyle = '#069';
      ctx.fillText('BrowserID', 4, 4);
      
      // Add a shape
      ctx.strokeStyle = '#AAF';
      ctx.beginPath();
      ctx.moveTo(50, 10);
      ctx.lineTo(90, 30);
      ctx.lineTo(50, 50);
      ctx.stroke();
      
      // Get the data URL
      return canvas.toDataURL().split(',')[1].substring(0, 32);
    } catch (e) {
      return null;
    }
  }

  /**
   * Create a WebGL fingerprint
   * 
   * @private
   * @returns {string|null} WebGL fingerprint or null
   */
  _getWebGLFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || 
                canvas.getContext('experimental-webgl');
      
      if (!gl) return null;
      
      // Collect WebGL info
      const info = {
        vendor: gl.getParameter(gl.VENDOR) || '',
        renderer: gl.getParameter(gl.RENDERER) || '',
        version: gl.getParameter(gl.VERSION) || '',
        shadingLang: gl.getParameter(gl.SHADING_LANGUAGE_VERSION) || '',
        // Limit the info to prevent excessive identifiability
        extensions: gl.getSupportedExtensions().slice(0, 5).join(',')
      };
      
      return JSON.stringify(info);
    } catch (e) {
      return null;
    }
  }

  /**
   * Check for presence of specific fonts
   * 
   * @private
   * @param {Array<string>} fontList - List of fonts to check
   * @returns {string} Font fingerprint string
   */
  _getFontFingerprint(fontList) {
    if (!document.body) return '';
    
    // Create test element
    const testString = 'mmmmmmmmmmlli';
    const testElement = document.createElement('span');
    testElement.style.fontSize = '72px';
    testElement.innerHTML = testString;
    
    // Temporary hide the element
    testElement.style.position = 'absolute';
    testElement.style.left = '-9999px';
    
    document.body.appendChild(testElement);
    
    // Collect information about font support
    const fontSupport = {};
    const baseWidth = {};
    const baseHeight = {};
    
    // Fallback fonts for width measurement
    const baseFonts = ['monospace', 'sans-serif', 'serif'];
    
    // Measure base fonts first
    for (const baseFont of baseFonts) {
      testElement.style.fontFamily = baseFont;
      baseWidth[baseFont] = testElement.offsetWidth;
      baseHeight[baseFont] = testElement.offsetHeight;
    }
    
    // Now check test fonts against base fonts
    for (const font of fontList) {
      let detected = false;
      
      for (const baseFont of baseFonts) {
        testElement.style.fontFamily = `'${font}', ${baseFont}`;
        
        // If width differs from base font, the custom font is available
        if (testElement.offsetWidth !== baseWidth[baseFont] ||
            testElement.offsetHeight !== baseHeight[baseFont]) {
          detected = true;
          break;
        }
      }
      
      fontSupport[font] = detected;
    }
    
    // Clean up
    document.body.removeChild(testElement);
    
    // We only use whether a font exists, not its metrics
    // This makes it less precise but more privacy-friendly
    return JSON.stringify(fontSupport);
  }
}

// Export for both browser and Node.js environments
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { DeviceFingerprint };
} else if (typeof window !== 'undefined') {
  window.DeviceFingerprint = DeviceFingerprint;
} 