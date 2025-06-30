const express = require('express');
const router = express.Router();

/**
 * GET /api/privacy/rights
 * Information about privacy rights available to users
 */
router.get('/rights', (req, res) => {
    res.json({
        success: true,
        message: 'Privacy rights information',
        ccpa: {
            name: 'California Consumer Privacy Act',
            applicable: 'California residents',
            rights: [
                'Right to know what personal information is collected',
                'Right to delete personal information',
                'Right to opt-out of the sale of personal information',
                'Right to non-discrimination for exercising privacy rights'
            ]
        },
        pipeda: {
            name: 'Personal Information Protection and Electronic Documents Act',
            applicable: 'Canadian residents',
            rights: [
                'Right to access personal information',
                'Right to correct inaccurate information',
                'Right to know how information is used',
                'Right to withdraw consent where applicable'
            ]
        }
    });
});

module.exports = router;
