/**
 * Event Bus for Microservice Communication
 * 
 * Provides event-driven architecture for decoupled service communication
 * Used for broadcasting user lifecycle events across services
 */

const EventEmitter = require('events');
const { logger } = require('../utils/logger');

class FairsEventBus extends EventEmitter {
  constructor() {
    super();
    this.setMaxListeners(50); // Allow more listeners for microservices
    
    // Log all events for debugging
    this.on('newListener', (event, listener) => {
      logger.debug('Event Bus: New listener registered', { event });
    });
  }

  /**
   * Emit user conversion event for data migration
   * @param {Object} eventData - Conversion event data
   */
  emitUserConversion(eventData) {
    const event = {
      type: 'user_converted_to_member',
      timestamp: new Date().toISOString(),
      version: '1.0',
      data: eventData
    };

    logger.info('Event Bus: Emitting user conversion event', {
      guestUserId: eventData.guestUserId,
      memberId: eventData.memberId,
      email: eventData.email?.substring(0, 3) + '***'
    });

    this.emit('user_converted_to_member', event);
    this.emit('user_lifecycle_event', event); // Generic lifecycle event
  }

  /**
   * Emit user creation event
   * @param {Object} eventData - User creation event data
   */
  emitUserCreated(eventData) {
    const event = {
      type: 'user_created',
      timestamp: new Date().toISOString(),
      version: '1.0',
      data: eventData
    };

    logger.info('Event Bus: Emitting user created event', {
      userId: eventData.userId,
      email: eventData.email?.substring(0, 3) + '***',
      isGuest: eventData.isGuest
    });

    this.emit('user_created', event);
    this.emit('user_lifecycle_event', event);
  }

  /**
   * Register event handlers for data migration
   */
  registerDataMigrationHandlers() {
    // Handle user conversion for checkout service data migration
    this.on('user_converted_to_member', async (event) => {
      try {
        logger.info('Event Bus: Processing user conversion for data migration', {
          eventType: event.type,
          memberId: event.data.memberId
        });

        // TODO: Implement data migration handlers
        // Example handlers that services could register:
        
        // 1. Migrate checkout service data
        // await migrateCheckoutData(event.data);
        
        // 2. Migrate payment service data
        // await migratePaymentData(event.data);
        
        // 3. Update analytics service
        // await updateAnalytics(event.data);
        
        // 4. Send welcome email
        // await sendWelcomeEmail(event.data);

        logger.info('Event Bus: User conversion processing completed', {
          memberId: event.data.memberId
        });

      } catch (error) {
        logger.error('Event Bus: Error processing user conversion event', {
          error: error.message,
          eventData: event.data
        });
      }
    });

    // Handle generic user lifecycle events
    this.on('user_lifecycle_event', async (event) => {
      logger.debug('Event Bus: User lifecycle event processed', {
        type: event.type,
        timestamp: event.timestamp
      });
    });
  }

  /**
   * Graceful shutdown - wait for pending events
   */
  async shutdown() {
    logger.info('Event Bus: Shutting down gracefully');
    
    // Give pending events time to complete
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    this.removeAllListeners();
    logger.info('Event Bus: Shutdown complete');
  }
}

// Create singleton instance
const eventBus = new FairsEventBus();

// Register default handlers
eventBus.registerDataMigrationHandlers();

module.exports = { eventBus };