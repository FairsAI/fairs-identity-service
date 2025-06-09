/**
 * KeyManager
 * 
 * Handles encryption key generation, storage, derivation, and rotation.
 * Uses the Web Crypto API when available and provides secure key management
 * based on device characteristics.
 */

const { DeviceFingerprint } = require('./DeviceFingerprint');

class KeyManager {
  /**
   * Creates a new KeyManager instance
   * 
   * @param {Object} options - Configuration options
   * @param {string} [options.namespace='fairs_keys'] - Namespace for key storage
   * @param {string} [options.storagePrefix='key_v'] - Prefix for stored keys
   * @param {number} [options.keyBits=256] - Key size in bits (128, 192, or 256)
   * @param {number} [options.defaultKeyVersion=1] - Default key version
   * @param {string} [options.defaultAlgorithm='AES-GCM'] - Default encryption algorithm
   * @param {Object} [options.fingerprint] - Device fingerprinting options
   * @param {function} [options.storageAdapter] - Custom storage adapter
   */
  constructor(options = {}) {
    this.namespace = options.namespace || 'fairs_keys';
    this.storagePrefix = options.storagePrefix || 'key_v';
    this.keyBits = options.keyBits || 256;
    this.currentKeyVersion = options.defaultKeyVersion || 1;
    this.algorithm = options.defaultAlgorithm || 'AES-GCM';
    
    // Device fingerprinting for key derivation
    this.fingerprintOptions = options.fingerprint || {};
    this.deviceFingerprint = new DeviceFingerprint();
    
    // Storage for keys
    this.storageAdapter = options.storageAdapter || window.localStorage;
    this.keys = new Map();
    
    // Check for Web Crypto API support
    this.cryptoSupported = typeof window !== 'undefined' && 
                          window.crypto && 
                          window.crypto.subtle;
                          
    // Server seed can be set later
    this.serverSeed = null;
  }

  /**
   * Initializes the key manager
   * 
   * @async
   * @param {string} [serverSeed] - Optional server provided seed
   * @returns {Promise<boolean>} Whether initialization was successful
   */
  async initialize(serverSeed) {
    try {
      if (serverSeed) {
        this.serverSeed = serverSeed;
      }
      
      // Get or generate the current version key
      await this.getCurrentKey();
      
      return true;
    } catch (error) {
      console.error('Error initializing KeyManager:', error);
      return false;
    }
  }

  /**
   * Sets a server seed to enhance key generation
   * 
   * @param {string} seed - Server-provided seed
   */
  setServerSeed(seed) {
    if (seed && typeof seed === 'string') {
      this.serverSeed = seed;
    }
  }

  /**
   * Gets the current key for encryption/decryption
   * 
   * @async
   * @returns {Promise<CryptoKey|Uint8Array>} The current encryption key
   */
  async getCurrentKey() {
    // Check if we already have the current key in memory
    if (this.keys.has(this.currentKeyVersion)) {
      return this.keys.get(this.currentKeyVersion);
    }
    
    // Attempt to load the key from storage
    let key = await this._loadKeyFromStorage(this.currentKeyVersion);
    
    // If no key exists, generate a new one
    if (!key) {
      key = await this._generateAndStoreKey(this.currentKeyVersion);
    }
    
    // Store key in memory for future use
    this.keys.set(this.currentKeyVersion, key);
    
    return key;
  }

  /**
   * Gets a specific key version
   * 
   * @async
   * @param {number} version - Key version to retrieve
   * @returns {Promise<CryptoKey|Uint8Array|null>} The requested key or null if not found
   */
  async getKeyByVersion(version) {
    // Check if we already have the key in memory
    if (this.keys.has(version)) {
      return this.keys.get(version);
    }
    
    // Attempt to load the key from storage
    const key = await this._loadKeyFromStorage(version);
    
    // Store key in memory if found
    if (key) {
      this.keys.set(version, key);
    }
    
    return key;
  }

  /**
   * Rotates to a new key version
   * 
   * @async
   * @param {number} newVersion - The new key version
   * @param {boolean} [generateImmediately=true] - Whether to generate the key immediately
   * @returns {Promise<boolean>} Whether rotation was successful
   */
  async rotateKey(newVersion, generateImmediately = true) {
    try {
      // Ensure new version is greater than current
      if (newVersion <= this.currentKeyVersion) {
        throw new Error('New key version must be greater than current version');
      }
      
      // Generate the new key if requested
      if (generateImmediately) {
        await this._generateAndStoreKey(newVersion);
      }
      
      // Update current version
      this.currentKeyVersion = newVersion;
      
      // Store current version in local storage for persistence
      this._storeCurrentKeyVersion();
      
      return true;
    } catch (error) {
      console.error('Error rotating key:', error);
      return false;
    }
  }

  /**
   * Creates a new encryption key and exports it for storage
   * 
   * @async
   * @param {number} version - Key version
   * @returns {Promise<CryptoKey|Uint8Array>} The generated key
   */
  async _generateAndStoreKey(version) {
    try {
      // Generate key material based on device fingerprint
      const keyMaterial = await this._generateKeyMaterial();
      
      // Generate actual encryption key
      const key = await this._deriveKey(keyMaterial);
      
      // Store the key
      await this._storeKey(version, key);
      
      return key;
    } catch (error) {
      console.error('Error generating key:', error);
      
      // Fallback to non-crypto API key generation
      return this._generateFallbackKey();
    }
  }

  /**
   * Loads a key from storage by version
   * 
   * @async
   * @param {number} version - Key version to load
   * @returns {Promise<CryptoKey|Uint8Array|null>} The loaded key or null
   */
  async _loadKeyFromStorage(version) {
    try {
      // Get stored key material
      const keyId = `${this.storagePrefix}${version}`;
      const storedKey = this.storageAdapter.getItem(`${this.namespace}.${keyId}`);
      
      if (!storedKey) {
        return null;
      }
      
      // If we don't have crypto API support, just use the stored key as raw bytes
      if (!this.cryptoSupported) {
        // Convert hex string to Uint8Array
        return this._hexToBytes(storedKey);
      }
      
      // For Web Crypto API, import the key
      return await this._importKey(storedKey);
    } catch (error) {
      console.error('Error loading key from storage:', error);
      return null;
    }
  }

  /**
   * Stores a key in storage
   * 
   * @async
   * @param {number} version - Key version
   * @param {CryptoKey|Uint8Array} key - The key to store
   * @returns {Promise<boolean>} Whether storage was successful
   */
  async _storeKey(version, key) {
    try {
      const keyId = `${this.storagePrefix}${version}`;
      let exportedKey;
      
      // Export CryptoKey or convert Uint8Array to string
      if (this.cryptoSupported && key instanceof CryptoKey) {
        const exported = await window.crypto.subtle.exportKey('raw', key);
        exportedKey = this._bytesToHex(new Uint8Array(exported));
      } else if (key instanceof Uint8Array) {
        exportedKey = this._bytesToHex(key);
      } else {
        throw new Error('Unsupported key format');
      }
      
      // Store in the adapter
      this.storageAdapter.setItem(`${this.namespace}.${keyId}`, exportedKey);
      
      // Also store current version for persistence
      this._storeCurrentKeyVersion();
      
      return true;
    } catch (error) {
      console.error('Error storing key:', error);
      return false;
    }
  }

  /**
   * Stores the current key version
   * 
   * @private
   */
  _storeCurrentKeyVersion() {
    try {
      this.storageAdapter.setItem(
        `${this.namespace}.current_version`, 
        this.currentKeyVersion.toString()
      );
    } catch (e) {
      // Silently fail - not critical
    }
  }

  /**
   * Generate key material from device fingerprint
   * 
   * @async
   * @returns {Promise<ArrayBuffer>} Key material for derivation
   */
  async _generateKeyMaterial() {
    try {
      // Get device fingerprint
      const fingerprint = await this.deviceFingerprint.generateFingerprint(this.fingerprintOptions);
      
      // Combine with server seed if available
      const seed = this.serverSeed ? `${fingerprint}:${this.serverSeed}` : fingerprint;
      
      // Generate key material using Web Crypto if available
      if (this.cryptoSupported) {
        const encoder = new TextEncoder();
        const data = encoder.encode(seed);
        
        // Use SHA-256 to create key material
        return await window.crypto.subtle.digest('SHA-256', data);
      } else {
        // Fallback - use the fingerprint directly
        return new TextEncoder().encode(fingerprint);
      }
    } catch (error) {
      console.error('Error generating key material:', error);
      
      // Last resort fallback
      const fallbackSeed = Date.now().toString() + Math.random().toString();
      return new TextEncoder().encode(fallbackSeed);
    }
  }

  /**
   * Derives a cryptographic key from key material
   * 
   * @async
   * @param {ArrayBuffer} keyMaterial - The key material to derive from
   * @returns {Promise<CryptoKey>} The derived key
   */
  async _deriveKey(keyMaterial) {
    if (!this.cryptoSupported) {
      // Fallback for browsers without crypto support
      return new Uint8Array(keyMaterial);
    }
    
    try {
      // Import the key material as a raw key
      const importedKey = await window.crypto.subtle.importKey(
        'raw',
        keyMaterial,
        { name: 'PBKDF2' },
        false,
        ['deriveBits', 'deriveKey']
      );
      
      // Use PBKDF2 to derive a strong key
      // Salt could be a fixed value or stored value
      const salt = new TextEncoder().encode(this.namespace);
      const iterations = 100000; // High iteration count for security
      
      // Derive the actual encryption key
      return await window.crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt,
          iterations,
          hash: 'SHA-256'
        },
        importedKey,
        {
          name: this.algorithm,
          length: this.keyBits
        },
        true, // Extractable
        ['encrypt', 'decrypt']
      );
    } catch (error) {
      console.error('Error deriving key:', error);
      
      // Return raw key material as a fallback
      return new Uint8Array(keyMaterial);
    }
  }

  /**
   * Imports a key from storage
   * 
   * @async
   * @param {string} hexKey - Hex-encoded key
   * @returns {Promise<CryptoKey>} The imported key
   */
  async _importKey(hexKey) {
    if (!this.cryptoSupported) {
      // Fallback for browsers without crypto support
      return this._hexToBytes(hexKey);
    }
    
    try {
      // Convert hex string to bytes
      const keyData = this._hexToBytes(hexKey);
      
      // Import the raw key
      return await window.crypto.subtle.importKey(
        'raw',
        keyData,
        {
          name: this.algorithm,
          length: this.keyBits
        },
        false, // Non-extractable for security
        ['encrypt', 'decrypt']
      );
    } catch (error) {
      console.error('Error importing key:', error);
      
      // Fallback to raw bytes
      return this._hexToBytes(hexKey);
    }
  }

  /**
   * Generates a fallback key when Web Crypto isn't available
   * 
   * @private
   * @returns {Uint8Array} A fallback key
   */
  _generateFallbackKey() {
    // Create a key with the appropriate number of bytes
    const keyBytes = this.keyBits / 8;
    const key = new Uint8Array(keyBytes);
    
    // Fill with pseudo-random values
    for (let i = 0; i < keyBytes; i++) {
      key[i] = Math.floor(Math.random() * 256);
    }
    
    return key;
  }

  /**
   * Converts a Uint8Array to a hex string
   * 
   * @private
   * @param {Uint8Array} bytes - The bytes to convert
   * @returns {string} Hex string representation
   */
  _bytesToHex(bytes) {
    return Array.from(bytes)
      .map(byte => byte.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Converts a hex string to a Uint8Array
   * 
   * @private
   * @param {string} hex - The hex string to convert
   * @returns {Uint8Array} The byte array
   */
  _hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
  }

  /**
   * Generates a random initialization vector (IV)
   * 
   * @returns {Uint8Array} A random IV
   */
  generateIV() {
    if (this.cryptoSupported) {
      return window.crypto.getRandomValues(new Uint8Array(12));
    }
    
    // Fallback
    const iv = new Uint8Array(12);
    for (let i = 0; i < 12; i++) {
      iv[i] = Math.floor(Math.random() * 256);
    }
    return iv;
  }

  /**
   * Encrypts data using the current key
   * 
   * @async
   * @param {string|Object} data - The data to encrypt
   * @param {Object} [options] - Encryption options
   * @param {number} [options.keyVersion] - Specific key version to use
   * @param {Uint8Array} [options.iv] - Custom initialization vector
   * @returns {Promise<Object>} The encrypted data with metadata
   */
  async encrypt(data, options = {}) {
    const keyVersion = options.keyVersion || this.currentKeyVersion;
    let iv = options.iv || this.generateIV();
    
    // Get the encryption key
    const key = await this.getKeyByVersion(keyVersion);
    
    if (!key) {
      throw new Error(`Encryption key for version ${keyVersion} not found`);
    }
    
    // Serialize data if it's an object
    const plaintext = typeof data === 'string' ? data : JSON.stringify(data);
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(plaintext);
    
    try {
      let encryptedData;
      
      if (this.cryptoSupported && key instanceof CryptoKey) {
        // Use Web Crypto API for encryption
        encryptedData = await window.crypto.subtle.encrypt(
          {
            name: this.algorithm,
            iv
          },
          key,
          encodedData
        );
        
        // Convert to Uint8Array
        encryptedData = new Uint8Array(encryptedData);
      } else {
        // Fallback encryption (simplified XOR with key as an example)
        encryptedData = this._fallbackEncrypt(encodedData, key, iv);
      }
      
      // Format the result
      return {
        version: keyVersion,
        iv: this._bytesToHex(iv),
        data: this._bytesToHex(encryptedData)
      };
    } catch (error) {
      console.error('Encryption error:', error);
      throw new Error('Failed to encrypt data');
    }
  }

  /**
   * Decrypts data using the specified key version
   * 
   * @async
   * @param {Object} encryptedPackage - The encrypted data package
   * @param {number} encryptedPackage.version - Key version used for encryption
   * @param {string} encryptedPackage.iv - Hex-encoded initialization vector
   * @param {string} encryptedPackage.data - Hex-encoded encrypted data
   * @param {Object} [options] - Decryption options
   * @param {boolean} [options.parseJson=true] - Whether to parse the result as JSON
   * @returns {Promise<string|Object>} The decrypted data
   */
  async decrypt(encryptedPackage, options = {}) {
    const { version, iv, data } = encryptedPackage;
    const parseJson = options.parseJson !== false;
    
    // Validate required fields
    if (!version || !iv || !data) {
      throw new Error('Invalid encrypted package format');
    }
    
    // Get the decryption key
    const key = await this.getKeyByVersion(version);
    
    if (!key) {
      throw new Error(`Decryption key for version ${version} not found`);
    }
    
    // Convert hex strings to byte arrays
    const ivBytes = this._hexToBytes(iv);
    const encryptedBytes = this._hexToBytes(data);
    
    try {
      let decryptedData;
      
      if (this.cryptoSupported && key instanceof CryptoKey) {
        // Use Web Crypto API for decryption
        const decryptedBuffer = await window.crypto.subtle.decrypt(
          {
            name: this.algorithm,
            iv: ivBytes
          },
          key,
          encryptedBytes
        );
        
        // Convert to string
        const decoder = new TextDecoder();
        decryptedData = decoder.decode(new Uint8Array(decryptedBuffer));
      } else {
        // Fallback decryption
        const decryptedBytes = this._fallbackDecrypt(encryptedBytes, key, ivBytes);
        const decoder = new TextDecoder();
        decryptedData = decoder.decode(decryptedBytes);
      }
      
      // Parse JSON if requested
      if (parseJson && decryptedData) {
        try {
          return JSON.parse(decryptedData);
        } catch (e) {
          // Return as string if not valid JSON
          return decryptedData;
        }
      }
      
      return decryptedData;
    } catch (error) {
      console.error('Decryption error:', error);
      throw new Error('Failed to decrypt data');
    }
  }

  /**
   * Fallback encryption when Web Crypto API isn't available
   * This is a basic XOR implementation and NOT secure for production
   * 
   * @private
   * @param {Uint8Array} data - Data to encrypt
   * @param {Uint8Array} key - Encryption key
   * @param {Uint8Array} iv - Initialization vector
   * @returns {Uint8Array} Encrypted data
   */
  _fallbackEncrypt(data, key, iv) {
    const result = new Uint8Array(data.length);
    
    for (let i = 0; i < data.length; i++) {
      // XOR with key and IV (rotating)
      result[i] = data[i] ^ key[i % key.length] ^ iv[i % iv.length];
    }
    
    return result;
  }

  /**
   * Fallback decryption when Web Crypto API isn't available
   * This is a basic XOR implementation and NOT secure for production
   * 
   * @private
   * @param {Uint8Array} data - Data to decrypt
   * @param {Uint8Array} key - Encryption key
   * @param {Uint8Array} iv - Initialization vector
   * @returns {Uint8Array} Decrypted data
   */
  _fallbackDecrypt(data, key, iv) {
    return this._fallbackEncrypt(data, key, iv); // XOR is symmetric
  }
}

// Export for both browser and Node.js environments
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { KeyManager };
} else if (typeof window !== 'undefined') {
  window.KeyManager = KeyManager;
} 