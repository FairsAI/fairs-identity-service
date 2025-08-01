# Address Management Migration Notice

## Overview
As of [current date], address management functionality has been migrated from the Identity Service to the Profile Service. This change improves service separation and aligns with our microservices architecture principles.

## Deprecated Endpoints
All address-related endpoints in the Identity Service are now deprecated and return HTTP 410 (Gone) status:

### Address Management Endpoints
- `POST /api/addresses` → Use `POST /api/v1/users/{userId}/addresses` via API Orchestrator
- `GET /api/addresses/:userId` → Use `GET /api/v1/users/{userId}/addresses` via API Orchestrator
- `GET /api/addresses/:userId/shipping` → Use `GET /api/v1/users/{userId}/addresses?type=shipping` via API Orchestrator
- `GET /api/addresses/:userId/billing` → Use `GET /api/v1/users/{userId}/addresses?type=billing` via API Orchestrator
- `PUT /api/addresses/:addressId` → Use `PUT /api/v1/users/{userId}/addresses/{addressId}` via API Orchestrator
- `DELETE /api/addresses/:addressId` → Use `DELETE /api/v1/users/{userId}/addresses/{addressId}` via API Orchestrator
- `POST /api/addresses/:addressId/default` → Use `PUT /api/v1/users/{userId}/addresses/{addressId}/default` via API Orchestrator
- `POST /api/addresses/:addressId/used` → Use `POST /api/v1/users/{userId}/addresses/{addressId}/track-usage` via API Orchestrator

### Checkout Registration
- `POST /api/checkout/register` → Use separate user creation and address endpoints via Checkout Service

## Migration Path

### For Service Clients
1. Update your service client to use the Profile Service endpoints via the API Orchestrator
2. Use JWT authentication instead of API keys
3. Include the `x-service-client` header to identify your service

### For Direct API Consumers
1. All address operations must go through the API Orchestrator
2. Update your base URL from direct Identity Service URLs to the orchestrator URL
3. Update endpoint paths as shown above

## Key Changes

### Authentication
- JWT Bearer tokens are required (no more API keys)
- Service-to-service calls require service tokens from Auth Service

### Data Structure
- Address data structure remains largely the same
- Profile Service uses camelCase field names consistently
- Address IDs are now UUIDs throughout

### New Features in Profile Service
- Better default address management
- Usage tracking for smart defaults
- Address validation endpoint
- Improved performance with dedicated service

## Timeline
- **Current**: Deprecated endpoints return 410 status with migration information
- **Future**: These endpoints will be removed entirely in a future version

## Support
For questions about the migration:
- Check the API documentation at https://docs.fairs.com/api/migration/addresses
- Contact the Platform team for assistance

## Database Migration
The `identity_service.user_addresses` table will be retained temporarily for data migration purposes. Do not add new features or modify this table.