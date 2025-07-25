FROM node:18-alpine

# Install curl for health checks
RUN apk add --no-cache curl

# Set working directory
WORKDIR /app

# Copy package files for dependency installation
COPY ./fairs-identity-service/package*.json ./

# Install production dependencies
RUN npm install --only=production && npm cache clean --force

# Copy application code
COPY ./fairs-identity-service/ ./

# Create necessary directories
RUN mkdir -p logs && chown -R node:node logs

# Switch to non-root user
USER node

# Expose service port
EXPOSE 3002

# Health check for identity service
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:3002/health || exit 1

# Start the service
CMD ["npm", "start"] 