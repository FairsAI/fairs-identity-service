/**
 * Database Schema Enforcement Middleware
 * 
 * Additional layer of protection beyond their existing validation
 * to ensure database operations comply with strict schemas
 */

const { logger } = require('../utils/logger');

class DatabaseSchemaEnforcement {
  constructor() {
    // Define strict database schemas per your 3-database architecture
    this.schemas = {
      fairs_checkout: {
        orders: {
          required: ['id', 'merchant_id', 'user_id', 'total_amount', 'currency', 'status'],
          optional: ['created_at', 'updated_at', 'metadata'],
          readOnly: ['id', 'created_at'],
          dataTypes: {
            id: 'string',
            merchant_id: 'string', 
            user_id: 'string',
            total_amount: 'number',
            currency: 'string',
            status: 'string',
            created_at: 'date',
            updated_at: 'date',
            metadata: 'object'
          },
          constraints: {
            total_amount: { min: 0.01, max: 1000000 },
            currency: { enum: ['USD', 'EUR', 'GBP', 'CAD'] },
            status: { enum: ['pending', 'processing', 'completed', 'failed', 'cancelled'] }
          }
        },
        payments: {
          required: ['id', 'order_id', 'amount', 'payment_method', 'status'],
          optional: ['created_at', 'updated_at', 'provider_transaction_id'],
          readOnly: ['id', 'created_at'],
          dataTypes: {
            id: 'string',
            order_id: 'string',
            amount: 'number',
            payment_method: 'string',
            status: 'string',
            provider_transaction_id: 'string',
            created_at: 'date',
            updated_at: 'date'
          },
          constraints: {
            amount: { min: 0.01, max: 1000000 },
            payment_method: { enum: ['credit_card', 'debit_card', 'paypal', 'bank_transfer'] },
            status: { enum: ['pending', 'processing', 'completed', 'failed', 'refunded'] }
          }
        }
      },
      fairs_ai: {
        ai_optimizations: {
          required: ['id', 'merchant_id', 'algorithm_used', 'confidence_score'],
          optional: ['created_at', 'updated_at', 'processing_time_ms'],
          readOnly: ['id', 'created_at'],
          dataTypes: {
            id: 'string',
            merchant_id: 'string',
            algorithm_used: 'string',
            confidence_score: 'number',
            processing_time_ms: 'number',
            created_at: 'date',
            updated_at: 'date'
          },
          constraints: {
            confidence_score: { min: 0, max: 1 },
            processing_time_ms: { min: 1, max: 30000 }
          }
        }
      },
      sdkpayments: {
        users: {
          required: ['id', 'email'],
          optional: ['first_name', 'last_name', 'phone', 'created_at', 'updated_at'],
          readOnly: ['id', 'created_at'],
          dataTypes: {
            id: 'string',
            email: 'string',
            first_name: 'string',
            last_name: 'string', 
            phone: 'string',
            created_at: 'date',
            updated_at: 'date'
          },
          constraints: {
            email: { pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ },
            phone: { pattern: /^\+?[1-9]\d{1,14}$/ }
          }
        }
      }
    };
  }

  /**
   * Validate data against schema before database operations
   */
  validateSchema(databaseType, tableName, operation, data) {
    const schema = this.schemas[databaseType]?.[tableName];
    
    if (!schema) {
      throw new Error(`No schema defined for ${databaseType}.${tableName}`);
    }

    const errors = [];

    // Check required fields for INSERT operations
    if (operation === 'INSERT') {
      for (const field of schema.required) {
        if (!(field in data)) {
          errors.push(`Missing required field: ${field}`);
        }
      }
    }

    // Validate data types and constraints
    for (const [field, value] of Object.entries(data)) {
      // Skip readonly fields in UPDATE operations
      if (operation === 'UPDATE' && schema.readOnly.includes(field)) {
        errors.push(`Cannot update readonly field: ${field}`);
        continue;
      }

      // Validate field exists in schema
      if (!schema.required.includes(field) && !schema.optional.includes(field)) {
        errors.push(`Unknown field: ${field}`);
        continue;
      }

      // Validate data type
      const expectedType = schema.dataTypes[field];
      if (!this.validateDataType(value, expectedType)) {
        errors.push(`Invalid data type for ${field}: expected ${expectedType}`);
        continue;
      }

      // Validate constraints
      const constraints = schema.constraints[field];
      if (constraints && !this.validateConstraints(value, constraints)) {
        errors.push(`Constraint violation for ${field}: ${JSON.stringify(constraints)}`);
      }
    }

    if (errors.length > 0) {
      logger.error('Schema validation failed:', {
        database: databaseType,
        table: tableName,
        operation,
        errors
      });
      throw new Error(`Schema validation failed: ${errors.join(', ')}`);
    }

    return true;
  }

  validateDataType(value, expectedType) {
    switch (expectedType) {
      case 'string':
        return typeof value === 'string';
      case 'number':
        return typeof value === 'number' && !isNaN(value);
      case 'date':
        return value instanceof Date || !isNaN(Date.parse(value));
      case 'object':
        return typeof value === 'object' && value !== null;
      default:
        return true;
    }
  }

  validateConstraints(value, constraints) {
    if (constraints.min !== undefined && value < constraints.min) return false;
    if (constraints.max !== undefined && value > constraints.max) return false;
    if (constraints.enum && !constraints.enum.includes(value)) return false;
    if (constraints.pattern && !constraints.pattern.test(value)) return false;
    
    return true;
  }

  /**
   * Express middleware factory
   */
  createMiddleware(databaseType, tableName, operation) {
    return (req, res, next) => {
      try {
        const data = req.validatedBody || req.body;
        this.validateSchema(databaseType, tableName, operation, data);
        next();
      } catch (error) {
        res.status(400).json({
          success: false,
          error: 'Schema validation failed',
          details: error.message
        });
      }
    };
  }
}

module.exports = new DatabaseSchemaEnforcement(); 