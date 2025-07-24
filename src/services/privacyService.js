/**
 * Privacy Service - CCPA & PIPEDA Compliance
 * US/Canada Production Ready Privacy Implementation
 */

const { logger } = require('../utils/logger');
const db = require('../database/db-connection');
const crypto = require('crypto');

class PrivacyService {
    constructor() {
        this.logger = logger;
        this.retentionPeriods = {
            user_data: 365 * 7,
            session_data: 365 * 2,
            marketing_data: 365 * 3,
            verification_logs: 365 * 1
        };
    }

    /**
     * CCPA Right to Know - Export all user data
     */
    async exportUserData(userId, email) {
        this.logger.info('Processing CCPA data export request', { userId, email });

        try {
            const user = await this.verifyUserIdentity(userId, email);
            if (!user) {
                throw new Error('User verification failed');
            }

            const requestId = await this.createPrivacyRequest(userId, 'DATA_EXPORT');
            const userData = await this.gatherCompleteUserData(userId);

            await this.logPrivacyAction(userId, 'DATA_EXPORTED', { requestId });

            return {
                success: true,
                requestId,
                exportDate: new Date().toISOString(),
                userData,
                legalBasis: 'CCPA Right to Know'
            };

        } catch (error) {
            this.logger.error('Failed to export user data', { userId, error: error.message });
            throw error;
        }
    }

    /**
     * CCPA Right to Delete
     */
    async deleteUserData(userId, email, confirmDeletion = false) {
        this.logger.info('Processing CCPA deletion request', { userId, email });

        try {
            const user = await this.verifyUserIdentity(userId, email);
            if (!user) {
                throw new Error('User verification failed');
            }

            const requestId = await this.createPrivacyRequest(userId, 'DATA_DELETION');

            if (!confirmDeletion) {
                const dataToDelete = await this.previewDataDeletion(userId);
                return {
                    success: true,
                    requestId,
                    preview: true,
                    dataToDelete,
                    confirmationRequired: true
                };
            }

            const deletionResult = await this.performDataDeletion(userId);

            await this.logPrivacyAction(userId, 'DATA_DELETED', { 
                requestId, 
                deletedRecords: deletionResult.recordsDeleted 
            });

            return {
                success: true,
                requestId,
                deletionDate: new Date().toISOString(),
                recordsDeleted: deletionResult.recordsDeleted,
                legalBasis: 'CCPA Right to Delete'
            };

        } catch (error) {
            this.logger.error('Failed to delete user data', { userId, error: error.message });
            throw error;
        }
    }

    /**
     * CCPA Right to Opt-Out of Sale
     */
    async optOutOfDataSale(userId, email) {
        this.logger.info('Processing CCPA opt-out request', { userId, email });

        try {
            const user = await this.verifyUserIdentity(userId, email);
            if (!user) {
                throw new Error('User verification failed');
            }

            const requestId = await this.createPrivacyRequest(userId, 'OPT_OUT_SALE');

            await this.updatePrivacyPreferences(userId, {
                data_sale_opt_out: true,
                marketing_opt_out: true,
                analytics_opt_out: true
            });

            await this.logPrivacyAction(userId, 'OPTED_OUT_SALE', { requestId });

            return {
                success: true,
                requestId,
                optOutDate: new Date().toISOString(),
                legalBasis: 'CCPA Right to Opt-Out'
            };

        } catch (error) {
            this.logger.error('Failed to process opt-out request', { userId, error: error.message });
            throw error;
        }
    }

    /**
     * Get privacy preferences
     */
    async getPrivacyPreferences(userId) {
        try {
            const query = `
                SELECT data_sale_opt_out, marketing_opt_out, analytics_opt_out, 
                       created_at, updated_at
                FROM user_privacy_preferences 
                WHERE user_id = $1
            `;
            
            const result = await db.query(query, [userId]);
            
            if (result.rows.length === 0) {
                await this.createDefaultPrivacyPreferences(userId);
                return this.getDefaultPrivacyPreferences();
            }

            return result.rows[0];

        } catch (error) {
            this.logger.error('Failed to get privacy preferences', { userId, error: error.message });
            throw error;
        }
    }

    /**
     * Update privacy preferences
     */
    async updatePrivacyPreferences(userId, preferences) {
        try {
            const query = `
                INSERT INTO user_privacy_preferences (
                    user_id, data_sale_opt_out, marketing_opt_out, 
                    analytics_opt_out, updated_at
                ) VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (user_id) 
                DO UPDATE SET 
                    data_sale_opt_out = $2,
                    marketing_opt_out = $3,
                    analytics_opt_out = $4,
                    updated_at = $5
                RETURNING *
            `;

            const values = [
                userId,
                preferences.data_sale_opt_out || false,
                preferences.marketing_opt_out || false,
                preferences.analytics_opt_out || false,
                new Date()
            ];

            const result = await db.query(query, values);
            return result.rows[0];

        } catch (error) {
            this.logger.error('Failed to update privacy preferences', { userId, error: error.message });
            throw error;
        }
    }

    // Private helper methods
    async verifyUserIdentity(userId, email) {
        try {
            const query = 'SELECT id, email FROM users WHERE id = $1 AND email = $2';
            const result = await db.query(query, [userId, email]);
            return result.rows[0] || null;
        } catch (error) {
            throw error;
        }
    }

    async createPrivacyRequest(userId, requestType) {
        try {
            const requestId = crypto.randomUUID();
            const query = `
                INSERT INTO privacy_requests (
                    id, user_id, request_type, status, created_at
                ) VALUES ($1, $2, $3, 'PROCESSING', $4)
                RETURNING id
            `;

            const result = await db.query(query, [requestId, userId, requestType, new Date()]);
            return result.rows[0].id;

        } catch (error) {
            throw error;
        }
    }

    async gatherCompleteUserData(userId) {
        try {
            return {
                personalInfo: await this.getUserPersonalInfo(userId),
                sessionData: await this.getUserSessionData(userId),
                transactionData: await this.getUserTransactionData(userId),
                preferencesData: await this.getPrivacyPreferences(userId)
            };
        } catch (error) {
            throw error;
        }
    }

    async getUserPersonalInfo(userId) {
        try {
            const query = `
                SELECT id, email, phone, first_name, last_name, 
                       created_at, updated_at, last_login
                FROM users WHERE id = $1
            `;
            const result = await db.query(query, [userId]);
            return result.rows[0] || {};
        } catch (error) {
            return {};
        }
    }

    async getUserSessionData(userId) {
        try {
            const query = `
                SELECT session_id, ip_address, user_agent, created_at
                FROM user_sessions 
                WHERE user_id = $1 
                ORDER BY created_at DESC 
                LIMIT 100
            `;
            const result = await db.query(query, [userId]);
            return result.rows || [];
        } catch (error) {
            return [];
        }
    }

    async getUserTransactionData(userId) {
        try {
            const query = `
                SELECT transaction_id, amount, currency, status, created_at
                FROM transactions 
                WHERE user_id = $1 
                ORDER BY created_at DESC
            `;
            const result = await db.query(query, [userId]);
            return result.rows || [];
        } catch (error) {
            return [];
        }
    }

    async previewDataDeletion(userId) {
        try {
            const userData = await this.gatherCompleteUserData(userId);
            
            return {
                personalInfo: Object.keys(userData.personalInfo || {}).length,
                sessionRecords: (userData.sessionData || []).length,
                transactionRecords: (userData.transactionData || []).length,
                note: 'Financial records may be retained for legal compliance'
            };
        } catch (error) {
            throw error;
        }
    }

    async performDataDeletion(userId) {
        const client = await db.getClient();
        let recordsDeleted = 0;

        try {
            await client.query('BEGIN');

            const sessionResult = await client.query('DELETE FROM user_sessions WHERE user_id = $1', [userId]);
            recordsDeleted += sessionResult.rowCount;

            await client.query(`
                UPDATE users SET 
                    email = 'deleted_' || id || '@privacy.local',
                    phone = null,
                    first_name = 'Deleted',
                    last_name = 'User',
                    updated_at = NOW()
                WHERE id = $1
            `, [userId]);
            recordsDeleted += 1;

            await client.query('COMMIT');
            return { recordsDeleted };

        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
    }

    async logPrivacyAction(userId, action, metadata = {}) {
        try {
            const query = `
                INSERT INTO privacy_audit_log (
                    user_id, action, metadata, created_at
                ) VALUES ($1, $2, $3, $4)
            `;

            await db.query(query, [
                userId,
                action,
                JSON.stringify(metadata),
                new Date()
            ]);
        } catch (error) {
            // Don't throw - logging failure shouldn't break main operation
        }
    }

    async createDefaultPrivacyPreferences(userId) {
        try {
            const query = `
                INSERT INTO user_privacy_preferences (
                    user_id, data_sale_opt_out, marketing_opt_out, 
                    analytics_opt_out, created_at, updated_at
                ) VALUES ($1, false, false, false, $2, $2)
                ON CONFLICT (user_id) DO NOTHING
            `;

            await db.query(query, [userId, new Date()]);
        } catch (error) {
            throw error;
        }
    }

    getDefaultPrivacyPreferences() {
        return {
            data_sale_opt_out: false,
            marketing_opt_out: false,
            analytics_opt_out: false,
            created_at: new Date(),
            updated_at: new Date()
        };
    }
}

module.exports = new PrivacyService(); 