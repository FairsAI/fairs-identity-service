# Identity Service JWT Usage Examples

## For Other Services Calling Identity Service

### 1. Using the Enhanced Client (Recommended)

```javascript
// In your service (e.g., Checkout Service)
const identityClient = require('./services/identity-client-enhanced');

// The client handles JWT token acquisition and renewal automatically
async function lookupUser(email) {
  try {
    const result = await identityClient.lookupUser({
      email: email,
      lookupType: 'email'
    });
    
    if (result.success && result.user) {
      console.log('User found:', result.user);
      return result.user;
    } else {
      console.log('User not found');
      return null;
    }
  } catch (error) {
    console.error('Identity lookup failed:', error);
    throw error;
  }
}
```

### 2. Direct API Call with JWT Token

```javascript
// Get service token (cached for performance)
const { ServiceClient } = require('@fairs/security-middleware');

const serviceClient = new ServiceClient({
  serviceId: process.env.SERVICE_ID,
  serviceSecret: process.env.SERVICE_SECRET,
  authServiceUrl: process.env.AUTH_SERVICE_URL
});

// Make authenticated request
async function directIdentityLookup(email) {
  const token = await serviceClient.getToken();
  
  const response = await fetch('http://fairs-api-orchestrator:4000/api/v1/identity/lookup', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      'X-Service-Client': 'checkout-service'
    },
    body: JSON.stringify({
      email: email,
      lookupType: 'email'
    })
  });
  
  return response.json();
}
```

### 3. Using API Key (Legacy - Still Supported)

```javascript
// Legacy method - will be deprecated
async function legacyIdentityLookup(email) {
  const response = await fetch('http://fairs-api-orchestrator:4000/api/v1/identity/lookup', {
    method: 'POST',
    headers: {
      'x-api-key': process.env.IDENTITY_API_KEY,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      email: email,
      lookupType: 'email'
    })
  });
  
  return response.json();
}
```

## Environment Variables Required

### For Services Using JWT Authentication

```bash
# Your service identity
SERVICE_ID=checkout-service
SERVICE_SECRET=checkout-service-secret-min-32-chars

# Auth service for token generation
AUTH_SERVICE_URL=http://fairs-auth-service:3005

# API Orchestrator (all service calls go through here)
API_ORCHESTRATOR_URL=http://fairs-api-orchestrator:4000
```

### For Legacy API Key Authentication

```bash
# API key for identity service access
IDENTITY_API_KEY=your-api-key-here

# API Orchestrator
API_ORCHESTRATOR_URL=http://fairs-api-orchestrator:4000
```

## Migration Path

1. **Current State**: Services can use either JWT tokens or API keys
2. **Migration Period**: Both methods work, but JWT is preferred
3. **Future State**: API keys will be deprecated, only JWT tokens accepted

## Benefits of JWT Service Tokens

1. **Better Security**: Tokens expire and can be revoked
2. **Fine-grained Permissions**: Each service gets only the permissions it needs
3. **Audit Trail**: Every request includes service identity
4. **No Shared Secrets**: Each service has its own credentials
5. **Automatic Renewal**: Tokens are renewed automatically by the client

## Testing Your Integration

```bash
# Test with JWT token
curl -X POST http://localhost:4000/api/v1/identity/lookup \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "lookupType": "email"}'

# Test with API key (legacy)
curl -X POST http://localhost:4000/api/v1/identity/lookup \
  -H "x-api-key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "lookupType": "email"}'
```

## Monitoring Authentication Methods

The Identity Service logs which authentication method is used:

```
INFO: Service authenticated {
  serviceId: 'checkout-service',
  serviceName: 'Checkout Service',
  authMethod: 'JWT Token',
  path: '/api/identity/lookup'
}

WARN: API key authentication used - please migrate to JWT service tokens {
  path: '/api/identity/lookup'
}
```

This helps track migration progress and identify services still using API keys.