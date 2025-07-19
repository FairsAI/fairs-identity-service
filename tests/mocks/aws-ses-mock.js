// Mock AWS SES client
const mockSESClient = {
  send: jest.fn()
};

const mockSendEmailCommand = jest.fn();

// Mock successful send response
const mockSuccessResponse = {
  MessageId: 'mock-message-id-123'
};

// Mock error response
const mockErrorResponse = {
  name: 'MessageRejected',
  message: 'Email rejected'
};

module.exports = {
  SESClient: jest.fn(() => mockSESClient),
  SendEmailCommand: mockSendEmailCommand,
  mockSESClient,
  mockSuccessResponse,
  mockErrorResponse,
  
  // Helper to setup successful mock
  mockSESSuccess: () => {
    mockSESClient.send.mockResolvedValue(mockSuccessResponse);
  },
  
  // Helper to setup error mock
  mockSESError: (error = mockErrorResponse) => {
    mockSESClient.send.mockRejectedValue(error);
  },
  
  // Helper to reset mocks
  resetMocks: () => {
    mockSESClient.send.mockReset();
    mockSendEmailCommand.mockReset();
  }
};