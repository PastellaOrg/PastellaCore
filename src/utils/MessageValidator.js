const logger = require('./logger');

/**
 *
 */
class MessageValidator {
  /**
   *
   * @param config
   */
  constructor(config = null) {
    // Define comprehensive message schemas
    this.messageSchemas = {
      // Authentication messages
      HANDSHAKE: {
        required: ['type', 'data'],
        properties: {
          type: { type: 'string', enum: ['HANDSHAKE'] },
          data: {
            type: 'object',
            required: ['networkId', 'nodeVersion', 'timestamp', 'nodeId'],
            properties: {
              networkId: { type: 'string', minLength: 1, description: 'Network identifier for compatibility check' },
              nodeVersion: { type: 'string', pattern: '^\\d+\\.\\d+\\.\\d+$', description: 'Semantic version' },
              timestamp: { type: 'number', minimum: 0, description: 'Unix timestamp' },
              nodeId: { type: 'string', minLength: 1, description: 'Node identifier' },
              listeningPort: {
                type: 'number',
                minimum: 1,
                maximum: 65535,
                description: 'Port the node is listening on for incoming connections',
              },
            },
          },
        },
      },

      HANDSHAKE_ACCEPTED: {
        required: ['type', 'data'],
        properties: {
          type: { type: 'string', enum: ['HANDSHAKE_ACCEPTED'] },
          data: {
            type: 'object',
            required: ['networkId', 'nodeVersion', 'timestamp'],
            properties: {
              networkId: { type: 'string', minLength: 1, description: 'Network identifier' },
              nodeVersion: { type: 'string', pattern: '^\\d+\\.\\d+\\.\\d+$', description: 'Semantic version' },
              timestamp: { type: 'number', minimum: 0, description: 'Unix timestamp' },
              message: { type: 'string', minLength: 1, description: 'Success message' },
            },
          },
        },
      },

      HANDSHAKE_REJECTED: {
        required: ['type', 'data'],
        properties: {
          type: { type: 'string', enum: ['HANDSHAKE_REJECTED'] },
          data: {
            type: 'object',
            required: ['reason', 'timestamp'],
            properties: {
              reason: { type: 'string', minLength: 1, description: 'Rejection reason' },
              expectedNetworkId: { type: 'string', minLength: 1, description: 'Expected network ID' },
              receivedNetworkId: { type: 'string', minLength: 1, description: 'Received network ID' },
              timestamp: { type: 'number', minimum: 0, description: 'Unix timestamp' },
              message: { type: 'string', minLength: 1, description: 'Detailed message' },
            },
          },
        },
      },

      HANDSHAKE_ERROR: {
        required: ['type', 'data'],
        properties: {
          type: { type: 'string', enum: ['HANDSHAKE_ERROR'] },
          data: {
            type: 'object',
            required: ['reason', 'timestamp'],
            properties: {
              reason: { type: 'string', minLength: 1, description: 'Error reason' },
              timestamp: { type: 'number', minimum: 0, description: 'Unix timestamp' },
            },
          },
        },
      },

      AUTH_CHALLENGE: {
        required: ['type', 'data'],
        properties: {
          type: { type: 'string', enum: ['AUTH_CHALLENGE'] },
          data: {
            type: 'object',
            required: ['challenge', 'timestamp', 'nodeId', 'signature'],
            properties: {
              challenge: { type: 'string', pattern: '^[a-fA-F0-9]{64}$', description: '64-character hex challenge' },
              timestamp: { type: 'number', minimum: 0, description: 'Unix timestamp' },
              nodeId: { type: 'string', pattern: '^[a-fA-F0-9]{64}$', description: '64-character hex node ID' },
              signature: { type: 'string', minLength: 1, description: 'Base64 signature' },
            },
          },
        },
      },

      AUTH_RESPONSE: {
        required: ['type', 'data'],
        properties: {
          type: { type: 'string', enum: ['AUTH_RESPONSE'] },
          data: {
            type: 'object',
            required: ['challenge', 'timestamp', 'nodeId', 'signature'],
            properties: {
              challenge: { type: 'string', pattern: '^[a-fA-F0-9]{64}$', description: '64-character hex challenge' },
              timestamp: { type: 'number', minimum: 0, description: 'Unix timestamp' },
              nodeId: { type: 'string', pattern: '^[a-fA-F0-9]{64}$', description: '64-character hex node ID' },
              signature: { type: 'string', minLength: 1, description: 'Base64 signature' },
            },
          },
        },
      },

      AUTH_SUCCESS: {
        required: ['type'],
        properties: {
          type: { type: 'string', enum: ['AUTH_SUCCESS'] },
        },
      },

      AUTH_FAILURE: {
        required: ['type', 'reason'],
        properties: {
          type: { type: 'string', enum: ['AUTH_FAILURE'] },
          reason: { type: 'string', minLength: 1, description: 'Failure reason' },
        },
      },

      // Blockchain messages
      QUERY_LATEST: {
        required: ['type'],
        properties: {
          type: { type: 'string', enum: ['QUERY_LATEST'] },
        },
      },

      QUERY_ALL: {
        required: ['type'],
        properties: {
          type: { type: 'string', enum: ['QUERY_ALL'] },
        },
      },

      RESPONSE_BLOCKCHAIN: {
        required: ['type', 'data'],
        properties: {
          type: { type: 'string', enum: ['RESPONSE_BLOCKCHAIN'] },
          data: {
            type: 'array',
            minItems: 1,
            description: 'Array of blocks',
          },
        },
      },

      NEW_BLOCK: {
        required: ['type', 'data'],
        properties: {
          type: { type: 'string', enum: ['NEW_BLOCK'] },
          data: {
            type: 'object',
            required: ['index', 'hash', 'previousHash', 'timestamp', 'transactions', 'nonce', 'difficulty'],
            properties: {
              index: { type: 'number', minimum: 0, description: 'Block index' },
              hash: { type: 'string', pattern: '^[a-fA-F0-9]{64}$', description: 'Block hash' },
              previousHash: { type: 'string', pattern: '^[a-fA-F0-9]{64}$', description: 'Previous block hash' },
              timestamp: { type: 'number', minimum: 0, description: 'Block timestamp' },
              transactions: { type: 'array', minItems: 1, description: 'Array of transactions' },
              nonce: { type: 'number', minimum: 0, description: 'Mining nonce' },
              difficulty: { type: 'number', minimum: 1, description: 'Block difficulty' },
              merkleRoot: { type: 'string', pattern: '^[a-fA-F0-9]{64}$', description: 'Merkle root hash' },
              algorithm: { type: 'string', enum: ['velora'], description: 'Mining algorithm used' },
            },
          },
        },
      },

      // Transaction messages
      QUERY_TRANSACTION_POOL: {
        required: ['type'],
        properties: {
          type: { type: 'string', enum: ['QUERY_TRANSACTION_POOL'] },
        },
      },

      RESPONSE_TRANSACTION_POOL: {
        required: ['type', 'data'],
        properties: {
          type: { type: 'string', enum: ['RESPONSE_TRANSACTION_POOL'] },
          data: {
            type: 'array',
            description: 'Array of transactions',
          },
        },
      },

      NEW_TRANSACTION: {
        required: ['type', 'data'],
        properties: {
          type: { type: 'string', enum: ['NEW_TRANSACTION'] },
          data: {
            type: 'object',
            required: ['id', 'inputs', 'outputs', 'timestamp'],
            properties: {
              id: { type: 'string', pattern: '^[a-fA-F0-9]{64}$', description: 'Transaction ID' },
              inputs: { type: 'array', description: 'Transaction inputs' },
              outputs: { type: 'array', minItems: 1, description: 'Transaction outputs' },
              timestamp: { type: 'number', minimum: 0, description: 'Transaction timestamp' },
              signature: { type: 'string', minLength: 1, description: 'Transaction signature' },
              fee: { type: 'number', minimum: 0, description: 'Transaction fee' },
              paymentId: { type: 'string', pattern: '^[a-fA-F0-9]{64}$', description: 'Payment ID (64-character hash)' },
              isCoinbase: { type: 'boolean', description: 'Is coinbase transaction' },
              tag: { type: 'string', description: 'Transaction tag' },
              nonce: { type: 'string', description: 'Transaction nonce' },
              expiresAt: { type: 'number', minimum: 0, description: 'Transaction expiration' },
              sequence: { type: 'number', minimum: 0, description: 'Transaction sequence' },
              atomicSequence: { type: 'string', description: 'Atomic sequence' },
            },
          },
        },
      },

      // Network messages
      SEED_NODE_INFO: {
        required: ['type', 'data'],
        properties: {
          type: { type: 'string', enum: ['SEED_NODE_INFO'] },
          data: {
            type: 'object',
            required: ['isSeedNode', 'maxConnections', 'currentConnections'],
            properties: {
              isSeedNode: { type: 'boolean', description: 'Whether this is a seed node' },
              maxConnections: { type: 'number', minimum: 1, maximum: 1000, description: 'Maximum connections' },
              currentConnections: { type: 'number', minimum: 0, description: 'Current connections' },
            },
          },
        },
      },

      HEARTBEAT: {
        required: ['type', 'data'],
        properties: {
          type: { type: 'string', enum: ['HEARTBEAT'] },
          data: {
            type: 'object',
            required: ['timestamp', 'nodeId'],
            properties: {
              timestamp: { type: 'number', minimum: 0, description: 'Unix timestamp' },
              nodeId: { type: 'string', pattern: '^[a-fA-F0-9]{64}$', description: '64-character hex node ID' },
              sequence: { type: 'number', minimum: 0, description: 'Heartbeat sequence number' },
            },
          },
        },
      },

      HEALTH_STATUS: {
        required: ['type', 'data'],
        properties: {
          type: { type: 'string', enum: ['HEALTH_STATUS'] },
          data: {
            type: 'object',
            required: ['nodeId', 'timestamp', 'peerCount', 'connectedCount', 'isPartitioned', 'blockchainHeight'],
            properties: {
              nodeId: { type: 'string', pattern: '^[a-fA-F0-9]{64}$', description: '64-character hex node ID' },
              timestamp: { type: 'number', minimum: 0, description: 'Unix timestamp' },
              peerCount: { type: 'number', minimum: 0, description: 'Total peer count' },
              connectedCount: { type: 'number', minimum: 0, description: 'Connected peer count' },
              isPartitioned: { type: 'boolean', description: 'Whether network is partitioned' },
              blockchainHeight: { type: 'number', minimum: 0, description: 'Current blockchain height' },
            },
          },
        },
      },

      REQUEST_PEER_LIST: {
        required: ['type', 'data'],
        properties: {
          type: { type: 'string', enum: ['REQUEST_PEER_LIST'] },
          data: {
            type: 'object',
            required: ['timestamp', 'requester'],
            properties: {
              timestamp: { type: 'number', minimum: 0, description: 'Unix timestamp' },
              requester: {
                type: 'string',
                pattern: '^[a-fA-F0-9]{64}$',
                description: '64-character hex node ID of requester',
              },
            },
          },
        },
      },

      PEER_LIST_RESPONSE: {
        required: ['type', 'data'],
        properties: {
          type: { type: 'string', enum: ['PEER_LIST_RESPONSE'] },
          data: {
            type: 'object',
            required: ['peers', 'timestamp', 'requester'],
            properties: {
              peers: { type: 'array', description: 'Array of peer URLs' },
              timestamp: { type: 'number', minimum: 0, description: 'Unix timestamp' },
              requester: {
                type: 'string',
                pattern: '^[a-fA-F0-9]{64}$',
                description: '64-character hex node ID of requester',
              },
            },
          },
        },
      },

      SEED_NODE_INFO: {
        required: ['type', 'data'],
        properties: {
          type: { type: 'string', enum: ['SEED_NODE_INFO'] },
          data: {
            type: 'object',
            required: ['nodeId', 'timestamp', 'seedNodes'],
            properties: {
              nodeId: { type: 'string', pattern: '^[a-fA-F0-9]{64}$', description: '64-character hex node ID' },
              timestamp: { type: 'number', minimum: 0, description: 'Unix timestamp' },
              seedNodes: { type: 'array', description: 'Array of seed node URLs' },
            },
          },
        },
      },

      // Mempool synchronization messages (Bitcoin-style)
      MEMPOOL_SYNC_REQUEST: {
        required: ['timestamp'],
        optional: ['networkId'],
        types: {
          timestamp: 'number',
          networkId: 'string',
        },
      },

      // Peer discovery and sharing messages
      PEER_LIST_REQUEST: {
        required: ['timestamp'],
        optional: ['networkId'],
        types: {
          timestamp: 'number',
          networkId: 'string',
        },
      },
      PEER_LIST_SHARE: {
        required: ['peers', 'timestamp'],
        optional: ['networkId'],
        types: {
          peers: 'array',
          timestamp: 'number',
          networkId: 'string',
        },
      },

      // Health check messages
      PING: {
        required: ['timestamp'],
        optional: [],
        types: {
          timestamp: 'number',
        },
      },
      PONG: {
        required: ['timestamp'],
        optional: [],
        types: {
          timestamp: 'number',
        },
      },

      MEMPOOL_SYNC_RESPONSE: {
        required: ['timestamp'],
        optional: ['status', 'message'],
        types: {
          timestamp: 'number',
          status: 'string',
          message: 'string',
        },
      },
      MEMPOOL_INV: {
        required: ['transactionHashes', 'count', 'timestamp'],
        optional: [],
        types: {
          transactionHashes: 'array',
          count: 'number',
          timestamp: 'number',
        },
      },
      MEMPOOL_GETDATA: {
        required: ['transactionHashes', 'count'],
        optional: [],
        types: {
          transactionHashes: 'array',
          count: 'number',
        },
      },
      MEMPOOL_TX: {
        required: ['transaction', 'hash'],
        optional: [],
        types: {
          transaction: 'object',
          hash: 'string',
        },
      },
      MEMPOOL_NOTFOUND: {
        required: ['hash', 'reason'],
        optional: [],
        types: {
          hash: 'string',
          reason: 'string',
        },
      },
      MEMPOOL_REJECT: {
        required: ['hash', 'reason', 'code'],
        optional: [],
        types: {
          hash: 'string',
          reason: 'string',
          code: 'number',
        },
      },
    };

    // Define validation rules
    this.validationRules = {
      maxMessageSize: (config?.memory?.maxMessageSize || 1024) * 1024, // Use config or default 1MB
      maxTimestampDrift: 5 * 60 * 1000, // 5 minutes timestamp drift
      maxBlockSize: (config?.memory?.maxBlockSize || 1024) * 1024, // Use config or default 1MB
      maxTransactionSize: (config?.memory?.maxTransactionSize || 100) * 1024, // Use config or default 100KB
      maxTransactionsPerBlock: 10000, // Max transactions per block
      maxInputsPerTransaction: 1000, // Max inputs per transaction
      maxOutputsPerTransaction: 1000, // Max outputs per transaction
    };
  }

  /**
   * Validate a message against its schema
   * @param message
   * @param peerAddress
   */
  validateMessage(message, peerAddress = 'unknown') {
    try {
      // Basic structure validation
      const basicValidation = this.validateBasicStructure(message);
      if (!basicValidation.valid) {
        return basicValidation;
      }

      // Size validation
      const sizeValidation = this.validateMessageSize(message);
      if (!sizeValidation.valid) {
        return sizeValidation;
      }

      // Schema validation
      const schemaValidation = this.validateAgainstSchema(message);
      if (!schemaValidation.valid) {
        return schemaValidation;
      }

      // Business logic validation
      const businessValidation = this.validateBusinessLogic(message);
      if (!businessValidation.valid) {
        return businessValidation;
      }

      return { valid: true, message: 'Message validation successful' };
    } catch (error) {
      logger.error('MESSAGE_VALIDATOR', `Validation error for ${peerAddress}: ${error.message}`);
      return { valid: false, error: 'Internal validation error', details: error.message };
    }
  }

  /**
   * Validate basic message structure
   * @param message
   */
  validateBasicStructure(message) {
    if (!message || typeof message !== 'object') {
      return { valid: false, error: 'Invalid message structure', details: 'Message must be an object' };
    }

    if (!message.type || typeof message.type !== 'string') {
      return { valid: false, error: 'Missing or invalid message type', details: 'Message type must be a string' };
    }

    if (message.type.length > 50) {
      return { valid: false, error: 'Message type too long', details: 'Message type exceeds 50 characters' };
    }

    return { valid: true };
  }

  /**
   * Validate message size
   * @param message
   */
  validateMessageSize(message) {
    const messageSize = JSON.stringify(message).length;

    if (messageSize > this.validationRules.maxMessageSize) {
      return {
        valid: false,
        error: 'Message too large',
        details: `Message size ${messageSize} exceeds maximum ${this.validationRules.maxMessageSize}`,
      };
    }

    return { valid: true };
  }

  /**
   * Validate message against schema
   * @param message
   */
  validateAgainstSchema(message) {
    const schema = this.messageSchemas[message.type];

    if (!schema) {
      return {
        valid: false,
        error: 'Unknown message type',
        details: `No schema found for message type: ${message.type}`,
      };
    }

    // Validate required fields
    const requiredValidation = this.validateRequiredFields(message, schema);
    if (!requiredValidation.valid) {
      return requiredValidation;
    }

    // Validate properties
    const propertiesValidation = this.validateProperties(message, schema, message.type);
    if (!propertiesValidation.valid) {
      return propertiesValidation;
    }

    return { valid: true };
  }

  /**
   * Validate required fields
   * @param message
   * @param schema
   */
  validateRequiredFields(message, schema) {
    if (!schema.required) {
      return { valid: true };
    }

    for (const field of schema.required) {
      if (!(field in message)) {
        return {
          valid: false,
          error: 'Missing required field',
          details: `Required field '${field}' is missing`,
        };
      }
    }

    return { valid: true };
  }

  /**
   * Validate properties
   * @param message
   * @param schema
   * @param messageType
   */
  validateProperties(message, schema, messageType = 'unknown') {
    if (!schema.properties) {
      return { valid: true };
    }

    for (const [field, value] of Object.entries(message)) {
      const fieldSchema = schema.properties[field];
      if (!fieldSchema) {
        return {
          valid: false,
          error: 'Unknown field',
          details: `Field '${field}' is not allowed in message type '${messageType}'`,
        };
      }

      const fieldValidation = this.validateField(value, fieldSchema, field, messageType);
      if (!fieldValidation.valid) {
        return fieldValidation;
      }
    }

    return { valid: true };
  }

  /**
   * Validate a single field
   * @param value
   * @param schema
   * @param fieldName
   * @param messageType
   */
  validateField(value, schema, fieldName, messageType = 'unknown') {
    // Special handling for paymentId - allow null values (when not used) or 64-char hash
    if (fieldName === 'paymentId' && value === null) {
      return { valid: true };
    }

    // Type validation
    if (schema.type) {
      let isValidType = false;

      if (schema.type === 'array') {
        isValidType = Array.isArray(value);
      } else {
        isValidType = typeof value === schema.type;
      }

      if (!isValidType) {
        return {
          valid: false,
          error: 'Invalid field type',
          details: `Field '${fieldName}' must be of type '${schema.type}', got '${typeof value}'`,
        };
      }
    }

    // String validations
    if (schema.type === 'string') {
      const stringValidation = this.validateStringField(value, schema, fieldName);
      if (!stringValidation.valid) {
        return stringValidation;
      }
    }

    // Number validations
    if (schema.type === 'number') {
      const numberValidation = this.validateNumberField(value, schema, fieldName);
      if (!numberValidation.valid) {
        return numberValidation;
      }
    }

    // Array validations
    if (schema.type === 'array') {
      const arrayValidation = this.validateArrayField(value, schema, fieldName);
      if (!arrayValidation.valid) {
        return arrayValidation;
      }
    }

    // Object validations
    if (schema.type === 'object') {
      const objectValidation = this.validateObjectField(value, schema, fieldName, messageType);
      if (!objectValidation.valid) {
        return objectValidation;
      }
    }

    // Boolean validations
    if (schema.type === 'boolean') {
      if (typeof value !== 'boolean') {
        return {
          valid: false,
          error: 'Invalid boolean field',
          details: `Field '${fieldName}' must be a boolean`,
        };
      }
    }

    return { valid: true };
  }

  /**
   * Validate string field
   * @param value
   * @param schema
   * @param fieldName
   */
  validateStringField(value, schema, fieldName) {
    if (typeof value !== 'string') {
      return {
        valid: false,
        error: 'Invalid string field',
        details: `Field '${fieldName}' must be a string`,
      };
    }

    // Length validation
    if (schema.minLength && value.length < schema.minLength) {
      return {
        valid: false,
        error: 'String too short',
        details: `Field '${fieldName}' must be at least ${schema.minLength} characters`,
      };
    }

    if (schema.maxLength && value.length > schema.maxLength) {
      return {
        valid: false,
        error: 'String too long',
        details: `Field '${fieldName}' must be at most ${schema.maxLength} characters`,
      };
    }

    // Pattern validation
    if (schema.pattern) {
      const regex = new RegExp(schema.pattern);
      if (!regex.test(value)) {
        return {
          valid: false,
          error: 'Invalid string pattern',
          details: `Field '${fieldName}' does not match required pattern`,
        };
      }
    }

    // Enum validation
    if (schema.enum && !schema.enum.includes(value)) {
      return {
        valid: false,
        error: 'Invalid enum value',
        details: `Field '${fieldName}' must be one of: ${schema.enum.join(', ')}`,
      };
    }

    return { valid: true };
  }

  /**
   * Validate number field
   * @param value
   * @param schema
   * @param fieldName
   */
  validateNumberField(value, schema, fieldName) {
    if (typeof value !== 'number' || isNaN(value)) {
      return {
        valid: false,
        error: 'Invalid number field',
        details: `Field '${fieldName}' must be a valid number`,
      };
    }

    // Range validation
    if (schema.minimum !== undefined && value < schema.minimum) {
      return {
        valid: false,
        error: 'Number too small',
        details: `Field '${fieldName}' must be at least ${schema.minimum}`,
      };
    }

    if (schema.maximum !== undefined && value > schema.maximum) {
      return {
        valid: false,
        error: 'Number too large',
        details: `Field '${fieldName}' must be at most ${schema.maximum}`,
      };
    }

    return { valid: true };
  }

  /**
   * Validate array field
   * @param value
   * @param schema
   * @param fieldName
   */
  validateArrayField(value, schema, fieldName) {
    if (!Array.isArray(value)) {
      return {
        valid: false,
        error: 'Invalid array field',
        details: `Field '${fieldName}' must be an array`,
      };
    }

    // Length validation
    if (schema.minItems && value.length < schema.minItems) {
      return {
        valid: false,
        error: 'Array too short',
        details: `Field '${fieldName}' must have at least ${schema.minItems} items`,
      };
    }

    if (schema.maxItems && value.length > schema.maxItems) {
      return {
        valid: false,
        error: 'Array too long',
        details: `Field '${fieldName}' must have at most ${schema.maxItems} items`,
      };
    }

    return { valid: true };
  }

  /**
   * Validate object field
   * @param value
   * @param schema
   * @param fieldName
   * @param messageType
   */
  validateObjectField(value, schema, fieldName, messageType = 'unknown') {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      return {
        valid: false,
        error: 'Invalid object field',
        details: `Field '${fieldName}' must be an object`,
      };
    }

    // Recursively validate object properties
    const objectValidation = this.validateProperties(value, schema, messageType);
    if (!objectValidation.valid) {
      return {
        valid: false,
        error: `Invalid object field: ${objectValidation.error}`,
        details: `Field '${fieldName}': ${objectValidation.details}`,
      };
    }

    return { valid: true };
  }

  /**
   * Validate business logic
   * @param message
   */
  validateBusinessLogic(message) {
    switch (message.type) {
      case 'NEW_BLOCK':
        return this.validateNewBlock(message.data);
      case 'NEW_TRANSACTION':
        return this.validateNewTransaction(message.data);
      case 'HANDSHAKE':
        return this.validateHandshake(message.data);
      case 'HANDSHAKE_ACCEPTED':
      case 'HANDSHAKE_REJECTED':
      case 'HANDSHAKE_ERROR':
        // These are response messages, basic validation is sufficient
        return { valid: true };
      case 'AUTH_CHALLENGE':
      case 'AUTH_RESPONSE':
        return this.validateAuthMessage(message.data);
      default:
        return { valid: true };
    }
  }

  /**
   * Validate new block message
   * @param blockData
   */
  validateNewBlock(blockData) {
    // Validate block size
    const blockSize = JSON.stringify(blockData).length;
    if (blockSize > this.validationRules.maxBlockSize) {
      return {
        valid: false,
        error: 'Block too large',
        details: `Block size ${blockSize} exceeds maximum ${this.validationRules.maxBlockSize}`,
      };
    }

    // Validate transaction count
    if (blockData.transactions.length > this.validationRules.maxTransactionsPerBlock) {
      return {
        valid: false,
        error: 'Too many transactions',
        details: `Block has ${blockData.transactions.length} transactions, maximum is ${this.validationRules.maxTransactionsPerBlock}`,
      };
    }

    // Validate timestamp
    const now = Date.now();
    const timestampDrift = Math.abs(now - blockData.timestamp);
    if (timestampDrift > this.validationRules.maxTimestampDrift) {
      return {
        valid: false,
        error: 'Invalid timestamp',
        details: `Block timestamp ${blockData.timestamp} is too far from current time ${now}`,
      };
    }

    // Validate hash format
    if (!/^[a-fA-F0-9]{64}$/.test(blockData.hash)) {
      return {
        valid: false,
        error: 'Invalid block hash',
        details: 'Block hash must be 64-character hex string',
      };
    }

    return { valid: true };
  }

  /**
   * Validate new transaction message
   * @param txData
   */
  validateNewTransaction(txData) {
    // Validate transaction size
    const txSize = JSON.stringify(txData).length;
    if (txSize > this.validationRules.maxTransactionSize) {
      return {
        valid: false,
        error: 'Transaction too large',
        details: `Transaction size ${txSize} exceeds maximum ${this.validationRules.maxTransactionSize}`,
      };
    }

    // Validate input/output counts
    if (txData.inputs.length > this.validationRules.maxInputsPerTransaction) {
      return {
        valid: false,
        error: 'Too many inputs',
        details: `Transaction has ${txData.inputs.length} inputs, maximum is ${this.validationRules.maxInputsPerTransaction}`,
      };
    }

    if (txData.outputs.length > this.validationRules.maxOutputsPerTransaction) {
      return {
        valid: false,
        error: 'Too many outputs',
        details: `Transaction has ${txData.outputs.length} outputs, maximum is ${this.validationRules.maxOutputsPerTransaction}`,
      };
    }

    // Validate transaction ID format
    if (!/^[a-fA-F0-9]{64}$/.test(txData.id)) {
      return {
        valid: false,
        error: 'Invalid transaction ID',
        details: 'Transaction ID must be 64-character hex string',
      };
    }

    return { valid: true };
  }

  /**
   * Validate handshake message
   * @param handshakeData
   */
  validateHandshake(handshakeData) {
    // Validate timestamp
    const now = Date.now();
    const timestampDrift = Math.abs(now - handshakeData.timestamp);
    if (timestampDrift > this.validationRules.maxTimestampDrift) {
      return {
        valid: false,
        error: 'Invalid handshake timestamp',
        details: `Handshake timestamp ${handshakeData.timestamp} is too far from current time ${now}`,
      };
    }

    // Validate network ID
    if (!handshakeData.networkId || typeof handshakeData.networkId !== 'string') {
      return {
        valid: false,
        error: 'Invalid network ID',
        details: 'Network ID is required and must be a string',
      };
    }

    // Validate node version format
    if (!handshakeData.nodeVersion || !/^\d+\.\d+\.\d+$/.test(handshakeData.nodeVersion)) {
      return {
        valid: false,
        error: 'Invalid node version',
        details: 'Node version must be in semantic version format (e.g., 1.0.0)',
      };
    }

    // Validate node ID
    if (!handshakeData.nodeId || typeof handshakeData.nodeId !== 'string') {
      return {
        valid: false,
        error: 'Invalid node ID',
        details: 'Node ID is required and must be a string',
      };
    }

    return { valid: true };
  }

  /**
   * Validate authentication messages
   * @param authData
   */
  validateAuthMessage(authData) {
    // Validate timestamp
    const now = Date.now();
    const timestampDrift = Math.abs(now - authData.timestamp);
    if (timestampDrift > this.validationRules.maxTimestampDrift) {
      return {
        valid: false,
        error: 'Invalid auth timestamp',
        details: `Auth timestamp ${authData.timestamp} is too far from current time ${now}`,
      };
    }

    return { valid: true };
  }

  /**
   * Get validation statistics
   */
  getValidationStats() {
    return {
      messageTypes: Object.keys(this.messageSchemas).length,
      validationRules: this.validationRules,
      maxMessageSize: this.validationRules.maxMessageSize,
      maxTimestampDrift: this.validationRules.maxTimestampDrift,
    };
  }

  /**
   * Update validation rules
   * @param newRules
   */
  updateValidationRules(newRules) {
    this.validationRules = { ...this.validationRules, ...newRules };
    logger.info('MESSAGE_VALIDATOR', 'Validation rules updated');
  }
}

module.exports = MessageValidator;
