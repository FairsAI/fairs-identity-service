const { SESClient, SendEmailCommand } = require('@aws-sdk/client-ses');
const winston = require('winston');

class AWSEmailService {
  constructor() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [
        new winston.transports.Console()
      ]
    });

    // Configure SES client
    this.sesClient = new SESClient({
      region: process.env.AWS_REGION || 'us-east-1',
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
      }
    });

    this.fromEmail = process.env.AWS_SES_FROM_EMAIL || 'noreply@fairs.com';
    this.replyToEmail = process.env.AWS_SES_REPLY_TO_EMAIL || this.fromEmail;
    
    // Rate limiting configuration
    this.maxSendRate = parseInt(process.env.AWS_SES_MAX_SEND_RATE || '14'); // SES default
    this.sendQueue = [];
    this.processing = false;
    
    // Email templates
    this.templates = {
      verification: {
        subject: 'Verify your Fairs account',
        html: (code) => `
          <!DOCTYPE html>
          <html>
          <head>
            <meta charset="UTF-8">
            <title>Verify your account</title>
            <style>
              body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
              .container { max-width: 600px; margin: 0 auto; padding: 20px; }
              .header { background-color: #f8f9fa; padding: 20px; text-align: center; }
              .code { font-size: 32px; font-weight: bold; color: #007bff; text-align: center; padding: 20px; margin: 20px 0; background-color: #f8f9fa; border-radius: 5px; }
              .footer { margin-top: 30px; font-size: 12px; color: #666; text-align: center; }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="header">
                <h1>Verify your Fairs account</h1>
              </div>
              <p>Thank you for using Fairs! Please use the verification code below to complete your sign-in:</p>
              <div class="code">${code}</div>
              <p>This code will expire in 10 minutes for your security.</p>
              <p>If you didn't request this code, please ignore this email.</p>
              <div class="footer">
                <p>This is an automated message from Fairs. Please do not reply to this email.</p>
              </div>
            </div>
          </body>
          </html>
        `,
        text: (code) => `
Verify your Fairs account

Thank you for using Fairs! Please use the verification code below to complete your sign-in:

${code}

This code will expire in 10 minutes for your security.

If you didn't request this code, please ignore this email.

This is an automated message from Fairs. Please do not reply to this email.
        `
      },
      welcome: {
        subject: 'Welcome to Fairs!',
        html: (name) => `
          <!DOCTYPE html>
          <html>
          <head>
            <meta charset="UTF-8">
            <title>Welcome to Fairs</title>
            <style>
              body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
              .container { max-width: 600px; margin: 0 auto; padding: 20px; }
              .header { background-color: #007bff; color: white; padding: 30px; text-align: center; }
              .content { padding: 30px 20px; }
              .button { display: inline-block; padding: 12px 30px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
              .footer { margin-top: 30px; font-size: 12px; color: #666; text-align: center; }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="header">
                <h1>Welcome to Fairs!</h1>
              </div>
              <div class="content">
                <p>Hi${name ? ' ' + name : ''},</p>
                <p>Welcome to Fairs! We're excited to have you on board.</p>
                <p>With Fairs, you can enjoy:</p>
                <ul>
                  <li>Seamless checkout across all your favorite merchants</li>
                  <li>Secure payment processing</li>
                  <li>Easy order tracking</li>
                  <li>Exclusive deals and offers</li>
                </ul>
                <center>
                  <a href="https://fairs.com/dashboard" class="button">Go to Dashboard</a>
                </center>
                <p>If you have any questions, our support team is here to help!</p>
              </div>
              <div class="footer">
                <p>&copy; 2024 Fairs. All rights reserved.</p>
              </div>
            </div>
          </body>
          </html>
        `,
        text: (name) => `
Welcome to Fairs!

Hi${name ? ' ' + name : ''},

Welcome to Fairs! We're excited to have you on board.

With Fairs, you can enjoy:
- Seamless checkout across all your favorite merchants
- Secure payment processing
- Easy order tracking
- Exclusive deals and offers

Visit your dashboard: https://fairs.com/dashboard

If you have any questions, our support team is here to help!

© 2024 Fairs. All rights reserved.
        `
      }
    };
  }

  async sendEmail(to, template, data) {
    try {
      const emailTemplate = this.templates[template];
      if (!emailTemplate) {
        throw new Error(`Unknown email template: ${template}`);
      }

      const params = {
        Destination: {
          ToAddresses: [to]
        },
        Message: {
          Body: {
            Html: {
              Charset: 'UTF-8',
              Data: emailTemplate.html(data)
            },
            Text: {
              Charset: 'UTF-8',
              Data: emailTemplate.text(data)
            }
          },
          Subject: {
            Charset: 'UTF-8',
            Data: emailTemplate.subject
          }
        },
        Source: this.fromEmail,
        ReplyToAddresses: [this.replyToEmail]
      };

      // Add to queue for rate limiting
      return await this.queueEmail(params);
    } catch (error) {
      this.logger.error('Failed to send email', {
        error: error.message,
        to,
        template
      });
      throw error;
    }
  }

  async queueEmail(params) {
    return new Promise((resolve, reject) => {
      this.sendQueue.push({ params, resolve, reject });
      if (!this.processing) {
        this.processQueue();
      }
    });
  }

  async processQueue() {
    if (this.processing || this.sendQueue.length === 0) {
      return;
    }

    this.processing = true;
    const delay = 1000 / this.maxSendRate; // Milliseconds between sends

    while (this.sendQueue.length > 0) {
      const { params, resolve, reject } = this.sendQueue.shift();
      
      try {
        const command = new SendEmailCommand(params);
        const response = await this.sesClient.send(command);
        
        this.logger.info('Email sent successfully', {
          messageId: response.MessageId,
          to: params.Destination.ToAddresses[0]
        });
        
        resolve({
          success: true,
          messageId: response.MessageId
        });
      } catch (error) {
        this.logger.error('SES send error', {
          error: error.message,
          to: params.Destination.ToAddresses[0]
        });
        
        // Handle specific SES errors
        if (error.name === 'MessageRejected') {
          reject(new Error('Email address is blacklisted or invalid'));
        } else if (error.name === 'MailFromDomainNotVerified') {
          reject(new Error('Sender email domain not verified in SES'));
        } else if (error.name === 'ConfigurationSetDoesNotExist') {
          reject(new Error('SES configuration error'));
        } else {
          reject(error);
        }
      }

      // Rate limiting delay
      if (this.sendQueue.length > 0) {
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }

    this.processing = false;
  }

  async sendVerificationCode(email, code) {
    return await this.sendEmail(email, 'verification', code);
  }

  async sendWelcomeEmail(email, name) {
    return await this.sendEmail(email, 'welcome', name);
  }

  // Test connection to SES
  async testConnection() {
    try {
      // Try to send a test email to the from address (self)
      const testParams = {
        Destination: {
          ToAddresses: [this.fromEmail]
        },
        Message: {
          Body: {
            Text: {
              Charset: 'UTF-8',
              Data: 'This is a test email from Fairs Identity Service to verify SES configuration.'
            }
          },
          Subject: {
            Charset: 'UTF-8',
            Data: 'Fairs SES Configuration Test'
          }
        },
        Source: this.fromEmail
      };

      const command = new SendEmailCommand(testParams);
      await this.sesClient.send(command);
      
      this.logger.info('SES connection test successful');
      return { success: true, message: 'SES connection successful' };
    } catch (error) {
      this.logger.error('SES connection test failed', { error: error.message });
      return { success: false, message: error.message };
    }
  }
}

module.exports = AWSEmailService;