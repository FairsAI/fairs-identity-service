/**
 * Data Transparency Service - Processing Transparency & Data Mapping
 * CCPA & PIPEDA Compliance Implementation
 */

const { logger } = require('../utils/logger');
const { dbConnection } = require('../database/db-connection');

class DataTransparencyService {
    constructor() {
        this.logger = logger;
        
        // Data categories for transparency reporting
        this.dataCategories = {
            PERSONAL_IDENTIFIERS: {
                name: 'Personal Identifiers',
                description: 'Information that identifies you personally',
                examples: ['Name', 'Email', 'Phone', 'User ID'],
                legalBasis: 'Contract Performance'
            },
            COMMERCIAL_INFO: {
                name: 'Commercial Information',
                description: 'Purchase history and commercial activity',
                examples: ['Purchase history', 'Cart contents', 'Payment methods'],
                legalBasis: 'Contract Performance'
            },
            INTERNET_ACTIVITY: {
                name: 'Internet Activity',
                description: 'Browsing behavior and device information',
                examples: ['IP address', 'Browser type', 'Pages visited'],
                legalBasis: 'Legitimate Interest'
            },
            INFERENCES: {
                name: 'Inferences',
                description: 'Predictions about preferences and behavior',
                examples: ['Purchase preferences', 'Risk scores'],
                legalBasis: 'Legitimate Interest'
            }
        };

        // Processing purposes for transparency
        this.processingPurposes = {
            SERVICE_PROVISION: {
                name: 'Service Provision',
                description: 'Providing our core commerce services',
                legalBasis: 'Contract Performance',
                retention: '7 years'
            },
            FRAUD_PREVENTION: {
                name: 'Fraud Prevention',
                description: 'Detecting and preventing fraudulent activity',
                legalBasis: 'Legitimate Interest',
                retention: '3 years'
            },
            ANALYTICS: {
                name: 'Analytics',
                description: 'Understanding service usage and improvements',
                legalBasis: 'Legitimate Interest',
                retention: '2 years'
            },
            MARKETING: {
                name: 'Marketing',
                description: 'Personalized marketing communications',
                legalBasis: 'Consent',
                retention: '3 years'
            }
        };
    }

    /**
     * Get comprehensive data processing transparency for a user
     */
    async getDataProcessingTransparency(userId) {
        try {
            this.logger.info('Getting data processing transparency', { userId });

            const [
                personalData,
                processingActivities,
                dataSharing,
                retentionInfo
            ] = await Promise.all([
                this.getPersonalDataInventory(userId),
                this.getProcessingActivities(userId),
                this.getDataSharingInfo(userId),
                this.getDataRetentionInfo(userId)
            ]);

            return {
                success: true,
                userId,
                generatedAt: new Date().toISOString(),
                dataInventory: personalData,
                processingActivities,
                dataSharing,
                retentionPolicies: retentionInfo,
                legalBasis: this.getComprehensiveLegalBasis(),
                userRights: this.getUserRights(),
                lastUpdated: new Date().toISOString()
            };

        } catch (error) {
            this.logger.error('Failed to get data processing transparency', { userId, error: error.message });
            throw error;
        }
    }

    /**
     * Get inventory of personal data we hold
     */
    async getPersonalDataInventory(userId) {
        try {
            const inventory = {
                PERSONAL_IDENTIFIERS: [],
                COMMERCIAL_INFO: [],
                INTERNET_ACTIVITY: [],
                INFERENCES: []
            };

            // Get user data
            const userQuery = `
                SELECT email, phone, first_name, last_name, created_at, last_login
                FROM identity_service.users WHERE id = $1
            `;
            const userResult = await dbConnection.query(userQuery, [userId]);
            
            if (userResult.length > 0) {
                const user = userResult[0];
                inventory.PERSONAL_IDENTIFIERS.push(
                    { field: 'email', value: user.email, collected: user.created_at },
                    { field: 'name', value: `${user.first_name} ${user.last_name}`, collected: user.created_at },
                    { field: 'phone', value: user.phone || 'Not provided', collected: user.created_at }
                );
            }

            // Get addresses
            const addressQuery = `
                SELECT address_line_1, city, state_province, country_code, created_at
                FROM identity_service.user_addresses WHERE user_id = $1
            `;
            const addressResult = await dbConnection.query(addressQuery, [userId]);
            
            addressResult.forEach(addr => {
                inventory.PERSONAL_IDENTIFIERS.push({
                    field: 'address',
                    value: `${addr.address_line_1}, ${addr.city}, ${addr.state_province}`,
                    collected: addr.created_at
                });
            });

            // Get payment methods (metadata only, no card details)
            const paymentQuery = `
                SELECT brand, last4, created_at
                FROM payment_service.user_payment_methods WHERE user_id = $1
            `;
            try {
                const paymentResult = await dbConnection.query(paymentQuery, [userId]);
                paymentResult.forEach(pm => {
                    inventory.COMMERCIAL_INFO.push({
                        field: 'payment_method',
                        value: `${pm.brand} ending in ${pm.last4}`,
                        collected: pm.created_at
                    });
                });
            } catch (paymentError) {
                // Payment service table may not exist
                this.logger.warn('Could not access payment data', { userId, error: paymentError.message });
            }

            // Get session data
            const sessionQuery = `
                SELECT ip_address, user_agent, created_at
                FROM identity_service.user_sessions 
                WHERE user_id = $1 
                ORDER BY created_at DESC 
                LIMIT 5
            `;
            try {
                const sessionResult = await dbConnection.query(sessionQuery, [userId]);
                sessionResult.forEach(session => {
                    inventory.INTERNET_ACTIVITY.push({
                        field: 'session_info',
                        value: `IP: ${session.ip_address}, Browser: ${session.user_agent.substring(0, 50)}...`,
                        collected: session.created_at
                    });
                });
            } catch (sessionError) {
                // Sessions table may not exist
                this.logger.warn('Could not access session data', { userId, error: sessionError.message });
            }

            return inventory;

        } catch (error) {
            this.logger.error('Failed to get personal data inventory', { userId, error: error.message });
            return {
                PERSONAL_IDENTIFIERS: [],
                COMMERCIAL_INFO: [],
                INTERNET_ACTIVITY: [],
                INFERENCES: []
            };
        }
    }

    /**
     * Get processing activities for the user
     */
    async getProcessingActivities(userId) {
        return [
            {
                purpose: 'Service Provision',
                description: 'Providing our core commerce services',
                legalBasis: 'Contract Performance',
                dataCategories: ['Personal Identifiers', 'Commercial Information'],
                retentionPeriod: '7 years',
                status: 'Active'
            },
            {
                purpose: 'Fraud Prevention',
                description: 'Detecting and preventing fraudulent activity',
                legalBasis: 'Legitimate Interest',
                dataCategories: ['Personal Identifiers', 'Internet Activity'],
                retentionPeriod: '3 years',
                status: 'Active'
            }
        ];
    }

    /**
     * Get data sharing information
     */
    async getDataSharingInfo(userId) {
        return {
            thirdPartySharing: [
                {
                    recipient: 'Payment Processor (Tilled)',
                    purpose: 'Payment Processing',
                    dataCategories: ['Payment Information'],
                    legalBasis: 'Contract Performance',
                    location: 'United States',
                    safeguards: 'PCI DSS Compliance'
                }
            ],
            dataSales: 'We do not sell personal information to third parties',
            crossBorderTransfers: {
                occurs: true,
                destinations: ['United States'],
                safeguards: 'Standard Contractual Clauses'
            }
        };
    }

    /**
     * Get data retention information
     */
    async getDataRetentionInfo(userId) {
        return {
            generalPolicy: 'Data is retained as long as necessary for the purposes collected',
            specificRetention: [
                {
                    dataType: 'Account Information',
                    retentionPeriod: '7 years after account closure',
                    reason: 'Legal compliance and fraud prevention'
                },
                {
                    dataType: 'Transaction Records',
                    retentionPeriod: '7 years',
                    reason: 'Financial regulation compliance'
                }
            ]
        };
    }

    /**
     * Get comprehensive legal basis information
     */
    getComprehensiveLegalBasis() {
        return {
            ccpa: {
                applicability: 'Applies to California residents',
                businessPurposes: [
                    'Providing services',
                    'Security and fraud prevention',
                    'Legal compliance'
                ]
            },
            pipeda: {
                applicability: 'Applies to Canadian residents',
                purposes: [
                    'Service provision and account management',
                    'Payment processing',
                    'Legal compliance'
                ]
            }
        };
    }

    /**
     * Get user rights information
     */
    getUserRights() {
        return {
            ccpaRights: {
                rightToKnow: {
                    description: 'Right to know what personal information is collected',
                    howToExercise: 'Submit request via /api/user-rights/request-data-export',
                    timeframe: '45 days'
                },
                rightToDelete: {
                    description: 'Right to delete personal information',
                    howToExercise: 'Submit request via /api/user-rights/request-data-deletion',
                    timeframe: '45 days'
                },
                rightToOptOut: {
                    description: 'Right to opt out of sale of personal information',
                    howToExercise: 'Submit request via /api/user-rights/opt-out-data-sale',
                    timeframe: 'Immediate'
                }
            },
            pipedaRights: {
                accessRight: {
                    description: 'Right to access personal information',
                    howToExercise: 'Contact privacy@fairs.com',
                    timeframe: '30 days'
                }
            },
            contact: {
                dataProtectionOfficer: 'privacy@fairs.com',
                phone: '1-800-FAIRS-PRIVACY'
            }
        };
    }

    /**
     * Log data access for audit purposes
     */
    async logDataAccess(userId, accessType, purpose) {
        try {
            const logQuery = `
                INSERT INTO data_access_log (user_id, access_type, purpose, accessed_at)
                VALUES ($1, $2, $3, $4)
            `;
            
            await dbConnection.query(logQuery, [userId, accessType, purpose, new Date()]);
            
        } catch (error) {
            // Don't throw - logging failure shouldn't break main operation
            this.logger.warn('Failed to log data access', { userId, error: error.message });
        }
    }
}

module.exports = new DataTransparencyService(); 