const DeviceFingerprintService = require('../../../src/services/device-fingerprint-service');

describe('DeviceFingerprintService', () => {
  let service;

  beforeEach(() => {
    service = new DeviceFingerprintService();
  });

  describe('Fingerprint Generation', () => {
    test('should generate fingerprint with all device data', () => {
      const deviceData = {
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        language: 'en-US',
        platform: 'MacIntel',
        screenResolution: '1920x1080',
        timezone: 'America/New_York',
        canvasFingerprint: 'abc123',
        webglVendor: 'Apple',
        fonts: ['Arial', 'Helvetica', 'Times New Roman']
      };

      const fingerprint = service.generateFingerprint(deviceData);

      expect(fingerprint).toHaveProperty('hash');
      expect(fingerprint).toHaveProperty('features');
      expect(fingerprint).toHaveProperty('entropy');
      expect(fingerprint).toHaveProperty('version');
      expect(fingerprint.hash).toHaveLength(64); // SHA-256 hex
      expect(fingerprint.entropy).toBeGreaterThan(0);
    });

    test('should handle minimal device data', () => {
      const deviceData = {
        userAgent: 'Mozilla/5.0'
      };

      const fingerprint = service.generateFingerprint(deviceData);

      expect(fingerprint).toHaveProperty('hash');
      expect(fingerprint.hash).toHaveLength(64);
      expect(fingerprint.entropy).toBeGreaterThanOrEqual(0);
    });

    test('should generate consistent hashes for identical data', () => {
      const deviceData = {
        userAgent: 'Mozilla/5.0',
        platform: 'MacIntel',
        language: 'en-US'
      };

      const fingerprint1 = service.generateFingerprint(deviceData);
      const fingerprint2 = service.generateFingerprint(deviceData);

      expect(fingerprint1.hash).toBe(fingerprint2.hash);
    });

    test('should generate different hashes for different data', () => {
      const deviceData1 = { userAgent: 'Mozilla/5.0', platform: 'MacIntel' };
      const deviceData2 = { userAgent: 'Mozilla/5.0', platform: 'Win32' };

      const fingerprint1 = service.generateFingerprint(deviceData1);
      const fingerprint2 = service.generateFingerprint(deviceData2);

      expect(fingerprint1.hash).not.toBe(fingerprint2.hash);
    });
  });

  describe('Entropy Calculation', () => {
    test('should calculate higher entropy for unique features', () => {
      const highEntropyFeatures = {
        canvasFingerprint: 'unique_canvas_data',
        audioFingerprint: 'unique_audio_data',
        webglVendor: 'NVIDIA Corporation',
        webglRenderer: 'GeForce GTX 1080',
        fonts: ['Arial', 'Helvetica', 'Times', 'Verdana', 'Georgia'],
        screenResolution: '3840x2160'
      };

      const lowEntropyFeatures = {
        platform: 'Win32',
        language: 'en-US'
      };

      const highEntropy = service.calculateEntropy(highEntropyFeatures);
      const lowEntropy = service.calculateEntropy(lowEntropyFeatures);

      expect(highEntropy).toBeGreaterThan(lowEntropy);
      expect(highEntropy).toBeLessThanOrEqual(100);
    });
  });

  describe('Fingerprint Comparison', () => {
    test('should return 100% similarity for identical fingerprints', () => {
      const deviceData = {
        userAgent: 'Mozilla/5.0',
        platform: 'MacIntel',
        screenResolution: '1920x1080'
      };

      const fingerprint1 = service.generateFingerprint(deviceData);
      const fingerprint2 = service.generateFingerprint(deviceData);

      const similarity = service.compareFingerprints(fingerprint1, fingerprint2);
      expect(similarity).toBe(100);
    });

    test('should return partial similarity for similar fingerprints', () => {
      const deviceData1 = {
        userAgent: 'Mozilla/5.0 Chrome/100.0',
        platform: 'MacIntel',
        screenResolution: '1920x1080',
        timezone: 'America/New_York'
      };

      const deviceData2 = {
        userAgent: 'Mozilla/5.0 Chrome/101.0', // Different version
        platform: 'MacIntel', // Same
        screenResolution: '1920x1080', // Same
        timezone: 'America/Los_Angeles' // Different
      };

      const fingerprint1 = service.generateFingerprint(deviceData1);
      const fingerprint2 = service.generateFingerprint(deviceData2);

      const similarity = service.compareFingerprints(fingerprint1, fingerprint2);
      expect(similarity).toBeGreaterThan(0);
      expect(similarity).toBeLessThan(100);
    });

    test('should return low similarity for very different fingerprints', () => {
      const deviceData1 = {
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        platform: 'MacIntel',
        screenResolution: '1920x1080',
        timezone: 'America/New_York',
        canvasFingerprint: 'canvas-mac-data-123'
      };

      const deviceData2 = {
        userAgent: 'Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 Chrome Mobile',
        platform: 'Linux armv81',
        screenResolution: '360x800',
        timezone: 'Asia/Tokyo',
        canvasFingerprint: 'canvas-android-data-456'
      };

      const fingerprint1 = service.generateFingerprint(deviceData1);
      const fingerprint2 = service.generateFingerprint(deviceData2);

      const similarity = service.compareFingerprints(fingerprint1, fingerprint2);
      expect(similarity).toBeLessThan(50);
    });
  });

  describe('Device Trust Assessment', () => {
    test('should identify trusted device with high similarity', () => {
      const currentFingerprint = service.generateFingerprint({
        userAgent: 'Mozilla/5.0',
        platform: 'MacIntel'
      });

      const trustedFingerprints = [
        service.generateFingerprint({
          userAgent: 'Mozilla/5.0',
          platform: 'MacIntel'
        })
      ];

      const result = service.isDeviceTrusted(currentFingerprint, trustedFingerprints, 85);

      expect(result.trusted).toBe(true);
      expect(result.similarity).toBeGreaterThanOrEqual(85);
      expect(result.matchedFingerprint).toBeDefined();
    });

    test('should reject untrusted device with low similarity', () => {
      const currentFingerprint = service.generateFingerprint({
        userAgent: 'Mozilla/5.0',
        platform: 'Win32'
      });

      const trustedFingerprints = [
        service.generateFingerprint({
          userAgent: 'Safari/14.0',
          platform: 'MacIntel'
        })
      ];

      const result = service.isDeviceTrusted(currentFingerprint, trustedFingerprints, 85);

      expect(result.trusted).toBe(false);
      expect(result.matchedFingerprint).toBe(null);
    });
  });

  describe('Device Metadata Extraction', () => {
    test('should extract browser information correctly', () => {
      const chromeUA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36';
      
      expect(service.extractBrowserName(chromeUA)).toBe('Chrome');
      expect(service.extractBrowserVersion(chromeUA)).toBe('100');
      expect(service.extractOSName(chromeUA)).toBe('macOS');
    });

    test('should detect mobile devices', () => {
      const mobileUA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15';
      const desktopUA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36';

      expect(service.isMobileDevice(mobileUA)).toBe(true);
      expect(service.isMobileDevice(desktopUA)).toBe(false);
    });

    test('should detect device type correctly', () => {
      const deviceData = {
        userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
        touchSupport: true
      };

      const metadata = service.extractDeviceMetadata(deviceData);
      expect(metadata.deviceType).toBe('mobile');
      expect(metadata.isMobile).toBe(true);
    });
  });

  describe('Font Normalization', () => {
    test('should filter to common fonts only', () => {
      const allFonts = [
        'Arial', 'Helvetica', 'ComicSansMS', 'Times New Roman',
        'SomeWeirdFont', 'AnotherUncommonFont', 'Verdana'
      ];

      const normalizedFonts = service.normalizefonts(allFonts);

      expect(normalizedFonts).toContain('Arial');
      expect(normalizedFonts).toContain('Helvetica');
      expect(normalizedFonts).toContain('Times New Roman');
      expect(normalizedFonts).toContain('Verdana');
      expect(normalizedFonts).not.toContain('SomeWeirdFont');
      expect(normalizedFonts).not.toContain('AnotherUncommonFont');
    });

    test('should return sorted font list', () => {
      const fonts = ['Verdana', 'Arial', 'Helvetica'];
      const normalized = service.normalizefonts(fonts);
      
      expect(normalized).toEqual(['Arial', 'Helvetica', 'Verdana']);
    });
  });
});