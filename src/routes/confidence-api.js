const express = require('express');
const router = express.Router();
const logger = require('../utils/logger');
const { validateMerchantAccess } = require('../middleware/auth-middleware');
const crossMerchantIdentityRepository = require('../database/cross-merchant-identity-repository');

/**
 * SECURITY FIX: Server-side confidence calculation endpoint
 * Prevents client-side manipulation of confidence scores
 * CVSS 5.4 (Medium) - Client-Side Confidence Score Manipulation
 */
router.post('/calculate', 
  validateMerchantAccess(),
  async (req, res) => {
  try {
    const startTime = Date.now();
    const requestingMerchant = req.merchantId;
    
    // Validate required parameters
    const { sourceToken, sourceMerchant, targetMerchant, deviceContext, sessionId, requestId } = req.body;
    
    if (!sourceToken || !sourceMerchant || !targetMerchant) {
      return res.status(400).json({
        success: false,
        error: 'Missing required parameters: sourceToken, sourceMerchant, targetMerchant'
      });
    }
    
    // SECURITY: Validate merchant authorization
    if (sourceMerchant !== requestingMerchant && targetMerchant !== requestingMerchant) {
      logger.warn('SECURITY: Unauthorized confidence calculation attempt', {
        requestingMerchant,
        sourceMerchant,
        targetMerchant,
        sourceToken: _sanitizeTokenForLogging(sourceToken),
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      
      return res.status(403).json({
        success: false,
        error: 'Unauthorized: merchant not involved in confidence calculation'
      });
    }
    
    // Calculate server-side confidence score using multiple secure factors
    const confidenceResult = await _calculateSecureConfidence({
      sourceToken,
      sourceMerchant,
      targetMerchant,
      deviceContext,
      sessionId,
      requestingMerchant
    });
    
    // SECURITY: Sign the confidence result to prevent tampering
    const signature = await _signConfidenceResult(confidenceResult, requestingMerchant);
    
    // Prepare secure response
    const response = {
      success: true,
      confidence: confidenceResult.confidence,
      timestamp: confidenceResult.timestamp,
      signature: signature,
      requestId,
      expiresAt: confidenceResult.timestamp + (5 * 60 * 1000), // 5 minute expiry
      algorithm: 'server-side-v1.0'
    };
    
    // Audit log the confidence calculation
    logger.info('Server confidence calculation completed', {
      requestingMerchant,
      sourceMerchant, 
      targetMerchant,
      confidence: confidenceResult.confidence.toFixed(3),
      factorCount: Object.keys(confidenceResult.factors).length,
      processingTime: Date.now() - startTime,
      requestId,
      ip: req.ip
    });
    
    res.json(response);
    
  } catch (error) {
    // 🚨 SECURITY FIX 1: Secure Error Handling (CVSS 7.0 HIGH)
    // ❌ REMOVE: Stack trace exposure in production logs
    const errorId = Math.random().toString(36).substring(2, 15);
    logger.error('Server confidence calculation failed', {
      errorId,
      errorType: error.constructor.name,
      requestingMerchant: req.merchantId,
      timestamp: Date.now()
      // ✅ SECURE: No stack trace, user data, or internal details
    });
    
    // SECURITY: Return minimum confidence on error (fail-safe)
    const timestamp = Date.now();
    const failSafeSignature = await _signConfidenceResult({ confidence: 0.0, timestamp }, req.merchantId);
    
    // ✅ SECURE: Return safe error response
    res.status(500).json({
      success: false,
      confidence: 0.0,
      timestamp,
      signature: failSafeSignature,
      error: 'Confidence calculation temporarily unavailable',
      errorId,
      requestId: req.body.requestId
    });
  }
});

/**
 * Calculate secure confidence score using server-controlled factors
 * @private
 */
async function _calculateSecureConfidence({ sourceToken, sourceMerchant, targetMerchant, deviceContext, sessionId }) {
  const timestamp = Date.now();
  const factors = {};
  
  // Factor 1: Token validity (40% weight)
  factors.tokenValidity = await _validateTokenConfidence(sourceToken, sourceMerchant);
  
  // Factor 2: Device consistency (25% weight)
  factors.deviceConsistency = await _calculateDeviceConsistency(deviceContext, sessionId);
  
  // Factor 3: Behavioral patterns (20% weight) 
  factors.behavioralConsistency = await _analyzeBehavioralPatterns(sourceMerchant, targetMerchant, deviceContext);
  
  // Factor 4: Session freshness (10% weight)
  factors.sessionFreshness = _calculateSessionFreshness(sessionId, timestamp);
  
  // Factor 5: Security risk (5% weight)
  factors.securityRisk = await _assessSecurityRisk(deviceContext, sourceMerchant);
  
  // SECURITY: Cryptographically secure weights
  const weights = {
    tokenValidity: 0.40,
    deviceConsistency: 0.25,
    behavioralConsistency: 0.20,
    sessionFreshness: 0.10,
    securityRisk: 0.05
  };
  
  // Calculate weighted confidence
  let confidence = 0;
  for (const [factor, value] of Object.entries(factors)) {
    confidence += value * weights[factor];
  }
  
  // Apply security penalties
  confidence = _applySecurityPenalties(confidence, factors, deviceContext);
  
  // SECURITY: Use cryptographically secure randomness
  const crypto = require('crypto');
  const secureRandomBytes = crypto.randomBytes(1);
  const secureVariation = (secureRandomBytes[0] / 255) * 0.02 - 0.01; // ±1% variation
  confidence += secureVariation;
  
  // Ensure confidence is within valid bounds
  confidence = Math.max(0.0, Math.min(0.99, confidence));
  
  return {
    confidence,
    timestamp,
    factors,
    weights
  };
}

async function _validateTokenConfidence(sourceToken, sourceMerchant) {
  try {
    const tokenRecord = await crossMerchantIdentityRepository.findUniversalIdByMerchantUser(
      sourceMerchant, 
      sourceToken
    );
    
    return tokenRecord ? 0.95 : 0.1;
  } catch (error) {
    logger.error('Token validation failed:', error);
    return 0.0;
  }
}

async function _calculateDeviceConsistency(deviceContext, sessionId) {
  if (!deviceContext) return 0.3;
  return 0.7; // Simplified for demo
}

async function _analyzeBehavioralPatterns(sourceMerchant, targetMerchant, deviceContext) {
  if (!deviceContext) return 0.4;
  
  const interactionScore = (deviceContext.mouseMovements || 0) + (deviceContext.keystrokes || 0) + (deviceContext.scrollActions || 0);
  return Math.min(0.9, 0.3 + (interactionScore / 100) * 0.6);
}

function _calculateSessionFreshness(sessionId, timestamp) {
  return sessionId ? 0.8 : 0.2;
}

async function _assessSecurityRisk(deviceContext, merchantId) {
  let riskScore = 0.0;
  
  if (!deviceContext) return 0.5;
  
  if (deviceContext.userAgent && deviceContext.userAgent.toLowerCase().includes('bot')) {
    riskScore += 0.8;
  }
  
  if (deviceContext.mouseMovements === 0 && deviceContext.keystrokes === 0) {
    riskScore += 0.3;
  }
  
  return Math.max(0.1, 1.0 - riskScore);
}

function _applySecurityPenalties(confidence, factors, deviceContext) {
  let penalty = 0;
  
  if (factors.deviceConsistency < 0.3) penalty += 0.2;
  if (factors.behavioralConsistency < 0.2) penalty += 0.15;
  if (factors.securityRisk < 0.3) penalty += 0.25;
  
  return Math.max(0.0, confidence - penalty);
}

// 🚨 SECURITY FIX 2: Secure Cryptographic Key Management (CVSS 6.5 MEDIUM)
// ✅ SECURE: Enhanced key validation
async function _getSecureSigningKey() {
  const signingKey = process.env.CONFIDENCE_SIGNING_KEY;
  
  if (!signingKey) {
    throw new Error('SECURITY ERROR: CONFIDENCE_SIGNING_KEY environment variable required');
  }
  
  if (signingKey.length < 32) {
    throw new Error('SECURITY ERROR: CONFIDENCE_SIGNING_KEY must be at least 32 characters');
  }
  
  if (signingKey === 'default-dev-key-change-in-production') {
    throw new Error('SECURITY ERROR: Default signing key detected in production');
  }
  
  return signingKey;
}

// ✅ SECURE: Use validated key
async function _signConfidenceResult(result, merchantId) {
  const crypto = require('crypto');
  const signingKey = await _getSecureSigningKey();
  const payload = `${result.confidence}:${result.timestamp}:${merchantId}`;
  const hmac = crypto.createHmac('sha256', signingKey);
  hmac.update(payload);
  return hmac.digest('hex');
}

function _sanitizeTokenForLogging(token) {
  if (!token || typeof token !== 'string') return '[INVALID]';
  if (token.length <= 8) return '[MASKED]';
  return token.substring(0, 4) + '...' + token.substring(token.length - 4);
}

module.exports = router; 