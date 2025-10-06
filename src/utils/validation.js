const { toAtomicUnits, fromAtomicUnits, formatAtomicUnits } = require('./atomicUnits.js');
const logger = require('./logger.js');

/**
 * Input validation and sanitization utilities
 */
class InputValidator {
  /**
   * Validate and sanitize a string input
   * @param {string} input - The input string
   * @param {object} options - Validation options
   * @returns {string|null} - Sanitized string or null if invalid
   */
  static validateString(input, options = {}) {
    const {
      minLength = 0,
      maxLength = 1000,
      pattern = null,
      required = false,
      trim = true,
      allowEmpty = false,
    } = options;

    // Check if input is required
    if (required && (!input || input === '')) {
      logger.debug('VALIDATION', `String validation failed: required field is empty`);
      return null;
    }

    // Handle empty input
    if (!input || input === '') {
      return allowEmpty ? '' : null;
    }

    // Ensure input is string
    const str = String(input);

    // Trim if requested
    const sanitized = trim ? str.trim() : str;

    // Check length constraints
    if (sanitized.length < minLength) {
      logger.debug('VALIDATION', `String validation failed: too short (${sanitized.length} < ${minLength})`);
      return null;
    }

    if (sanitized.length > maxLength) {
      logger.debug('VALIDATION', `String validation failed: too long (${sanitized.length} > ${maxLength})`);
      return null;
    }

    // Check pattern if provided
    if (pattern && !pattern.test(sanitized)) {
      logger.debug('VALIDATION', `String validation failed: pattern mismatch`);
      return null;
    }

    return sanitized;
  }

  /**
   * Validate and sanitize a number input
   * @param {any} input - The input value
   * @param {object} options - Validation options
   * @returns {number|null} - Validated number or null if invalid
   */
  static validateNumber(input, options = {}) {
    const { min = -Infinity, max = Infinity, integer = false, required = false } = options;

    // Check if input is required
    if (required && (input === null || input === undefined || input === '')) {
      logger.debug('VALIDATION', `Number validation failed: required field is empty`);
      return null;
    }

    // Handle empty input
    if (input === null || input === undefined || input === '') {
      return null;
    }

    // Convert to number
    const num = Number(input);

    // Check if it's a valid number
    if (isNaN(num)) {
      logger.debug('VALIDATION', `Number validation failed: not a valid number`);
      return null;
    }

    // Check integer constraint
    if (integer && !Number.isInteger(num)) {
      logger.debug('VALIDATION', `Number validation failed: not an integer`);
      return null;
    }

    // Check range constraints
    if (num < min) {
      logger.debug('VALIDATION', `Number validation failed: too small (${num} < ${min})`);
      return null;
    }

    if (num > max) {
      logger.debug('VALIDATION', `Number validation failed: too large (${num} > ${max})`);
      return null;
    }

    return num;
  }

  /**
   * Validate and sanitize a cryptocurrency amount with decimal precision
   * @param {any} input - The amount input
   * @param {object} options - Validation options
   * @param {number} decimals - Number of decimal places allowed (default: 8)
   * @returns {number|null} - Validated amount or null if invalid
   */
  static validateAmount(input, options = {}, decimals = 8) {
    const { min = 0, max = Infinity, required = false } = options;

    // First validate as a regular number
    const num = this.validateNumber(input, { min, max, required });
    if (num === null) {
      return null;
    }

    // Check decimal precision
    const decimalPlaces = this.getDecimalPlaces(num);
    if (decimalPlaces > decimals) {
      logger.debug('VALIDATION', `Amount validation failed: too many decimal places (${decimalPlaces} > ${decimals})`);
      return null;
    }

    return num;
  }

  /**
   * Get the number of decimal places in a number
   * @param {number} num - The number to check
   * @returns {number} - Number of decimal places
   */
  static getDecimalPlaces(num) {
    if (Math.floor(num) === num) return 0;
    const str = num.toString();
    if (str.indexOf('.') !== -1 && str.indexOf('e-') === -1) {
      return str.split('.')[1].length;
    }
    if (str.indexOf('e-') !== -1) {
      const match = str.match(/e-(\d+)/);
      return match ? parseInt(match[1]) : 0;
    }
    return 0;
  }

  /**
   * Validate and sanitize an email address
   * @param {string} input - The email input
   * @param {object} options - Validation options
   * @returns {string|null} - Sanitized email or null if invalid
   */
  static validateEmail(input, options = {}) {
    const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

    return this.validateString(input, {
      ...options,
      pattern: emailPattern,
      maxLength: 254, // RFC 5321 limit
    });
  }

  /**
   * Validate and sanitize a URL
   * @param {string} input - The URL input
   * @param {object} options - Validation options
   * @returns {string|null} - Sanitized URL or null if invalid
   */
  static validateUrl(input, options = {}) {
    try {
      const url = new URL(input);
      return url.toString();
    } catch (error) {
      logger.debug('VALIDATION', `URL validation failed: ${error.message}`);
      return null;
    }
  }

  /**
   * Validate and sanitize a wallet address
   * @param {string} input - The address input
   * @param {object} options - Validation options
   * @returns {string|null} - Sanitized address or null if invalid
   */
  static validateAddress(input, options = {}) {
    const addressPattern = /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/;

    return this.validateString(input, {
      ...options,
      pattern: addressPattern,
      minLength: 26,
      maxLength: 35,
    });
  }

  /**
   * Validate and sanitize a transaction hash
   * @param {string} input - The hash input
   * @param {object} options - Validation options
   * @returns {string|null} - Sanitized hash or null if invalid
   */
  static validateHash(input, options = {}) {
    const hashPattern = /^[a-fA-F0-9]{64}$/;

    return this.validateString(input, {
      ...options,
      pattern: hashPattern,
      minLength: 64,
      maxLength: 64,
    });
  }

  /**
   * Validate and sanitize a payment ID (64 hex characters)
   * @param {string} input - The payment ID input
   * @param {object} options - Validation options
   * @returns {string|null} - Sanitized payment ID or null if invalid
   */
  static validatePaymentId(input, options = {}) {
    const paymentIdPattern = /^[a-fA-F0-9]{64}$/;

    return this.validateString(input, {
      ...options,
      pattern: paymentIdPattern,
      minLength: 64,
      maxLength: 64,
    });
  }

  /**
   * Validate and sanitize a port number
   * @param {any} input - The port input
   * @param {object} options - Validation options
   * @returns {number|null} - Validated port or null if invalid
   */
  static validatePort(input, options = {}) {
    return this.validateNumber(input, {
      ...options,
      min: 1,
      max: 65535,
      integer: true,
    });
  }

  /**
   * Validate and sanitize an object with schema
   * @param {object} input - The input object
   * @param {object} schema - Validation schema
   * @returns {object | null} - Validated object or null if invalid
   */
  static validateObject(input, schema) {
    if (!input || typeof input !== 'object') {
      logger.debug('VALIDATION', `Object validation failed: not an object`);
      return null;
    }

    const result = {};

    for (const [key, validator] of Object.entries(schema)) {
      const value = input[key];
      const validated = validator(value);

      if (validated === null) {
        logger.debug('VALIDATION', `Object validation failed: invalid field '${key}'`);
        return null;
      }

      result[key] = validated;
    }

    return result;
  }

  /**
   * Validate and sanitize an array
   * @param {Array} input - The input array
   * @param {Function} itemValidator - Validator function for each item
   * @param {object} options - Validation options
   * @returns {Array|null} - Validated array or null if invalid
   */
  static validateArray(input, itemValidator, options = {}) {
    const { minLength = 0, maxLength = 1000, required = false } = options;

    // Check if input is required
    if (required && (!input || !Array.isArray(input))) {
      logger.debug('VALIDATION', `Array validation failed: required field is not an array`);
      return null;
    }

    // Handle empty input
    if (!input || !Array.isArray(input)) {
      return [];
    }

    // Check length constraints
    if (input.length < minLength) {
      logger.debug('VALIDATION', `Array validation failed: too short (${input.length} < ${minLength})`);
      return null;
    }

    if (input.length > maxLength) {
      logger.debug('VALIDATION', `Array validation failed: too long (${input.length} > ${maxLength})`);
      return null;
    }

    // Validate each item
    const result = [];
    for (let i = 0; i < input.length; i++) {
      const validated = itemValidator(input[i]);
      if (validated === null) {
        logger.debug('VALIDATION', `Array validation failed: invalid item at index ${i}`);
        return null;
      }
      result.push(validated);
    }

    return result;
  }

  /**
   * Sanitize HTML content to prevent XSS
   * @param {string} input - The input string
   * @returns {string} - Sanitized string
   */
  static sanitizeHtml(input) {
    if (!input || typeof input !== 'string') {
      return '';
    }

    return (
      input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;')
        
        .replace(/javascript:/gi, '')
        .replace(/on\w+\s*=/gi, '')
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '')
    );
  }

  /**
   * Sanitize SQL content to prevent injection
   * @param {string} input - The input string
   * @returns {string} - Sanitized string
   */
  static sanitizeSql(input) {
    if (!input || typeof input !== 'string') {
      return '';
    }

    // Remove SQL injection patterns
    return (
      input
        .replace(/['";]/g, '')
        .replace(/--/g, '')
        .replace(/\/\*/g, '')
        .replace(/\*\//g, '')
        .replace(/union\s+select/gi, '')
        .replace(/drop\s+table/gi, '')
        .replace(/delete\s+from/gi, '')
        .replace(/insert\s+into/gi, '')
        .replace(/update\s+set/gi, '')
        
        .replace(/exec\s*\(/gi, '')
        .replace(/xp_cmdshell/gi, '')
        .replace(/sp_executesql/gi, '')
        .replace(/waitfor\s+delay/gi, '')
        .replace(/benchmark\s*\(/gi, '')
    );
  }

  /**
   * CRITICAL: Validate cryptocurrency address with enhanced security
   * @param {string} input - The address input
   * @param {object} options - Validation options
   * @returns {string|null} - Sanitized address or null if invalid
   */
  static validateCryptocurrencyAddress(input, options = {}) {
    const { minLength = 26, maxLength = 35, required = false, allowTestnet = false } = options;

    // Basic string validation
    const sanitized = this.validateString(input, { minLength, maxLength, required });
    if (!sanitized) return null;

    
    const mainnetPattern = /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/;
    const testnetPattern = /^[2mn][a-km-zA-HJ-NP-Z1-9]{25,34}$/;

    const isValidMainnet = mainnetPattern.test(sanitized);
    const isValidTestnet = allowTestnet && testnetPattern.test(sanitized);

    if (!isValidMainnet && !isValidTestnet) {
      logger.debug('VALIDATION', `Cryptocurrency address validation failed: invalid format`);
      return null;
    }

    
    const attackPatterns = [
      /^0x[a-fA-F0-9]{40}$/, // Ethereum address (potential confusion)
      /^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$/, // Litecoin address (potential confusion)
      /^[DA][a-km-zA-HJ-NP-Z1-9]{33}$/, // Dogecoin address (potential confusion)
    ];

    for (const pattern of attackPatterns) {
      if (pattern.test(sanitized)) {
        logger.warn('VALIDATION', `⚠️  Potential address confusion attack detected: ${sanitized}`);
        return null;
      }
    }

    return sanitized;
  }

  /**
   * CRITICAL: Validate transaction data with comprehensive security checks
   * @param {object} transaction - The transaction object
   * @returns {object | null} - Validated transaction or null if invalid
   */
  static validateTransaction(transaction) {
    if (!transaction || typeof transaction !== 'object') {
      return null;
    }

    try {
      const validated = {
        inputs: [],
        outputs: [],
        fee: 0,
        timestamp: Date.now(),
      };

      // Validate inputs
      if (Array.isArray(transaction.inputs)) {
        for (const input of transaction.inputs) {
          if (!input || typeof input !== 'object') continue;

          const validatedInput = {
            txId: this.validateHash(input.txId, { required: true }),
            outputIndex: this.validateNumber(input.outputIndex, { min: 0, required: true }),
            signature: this.validateString(input.signature, { required: true, maxLength: 200 }),
            publicKey: this.validateString(input.publicKey, { required: true, maxLength: 200 }),
          };

          if (Object.values(validatedInput).some(v => v === null)) {
            logger.warn('VALIDATION', `⚠️  Invalid transaction input detected`);
            return null;
          }

          validated.inputs.push(validatedInput);
        }
      }

      // Validate outputs
      if (Array.isArray(transaction.outputs)) {
        for (const output of transaction.outputs) {
          if (!output || typeof output !== 'object') continue;

          const validatedOutput = {
            address: this.validateCryptocurrencyAddress(output.address, { required: true }),
            amount: this.validateAmount(output.amount, { min: 1, required: true }), // 1 atomic unit minimum
          };

          if (Object.values(validatedOutput).some(v => v === null)) {
            logger.warn('VALIDATION', `⚠️  Invalid transaction output detected`);
            return null;
          }

          validated.outputs.push(validatedOutput);
        }
      }

      // Validate fee
      validated.fee = this.validateAmount(transaction.fee, { min: 0, required: true });
      if (validated.fee === null) return null;

      // Validate timestamp
      if (transaction.timestamp) {
        const timestamp = this.validateNumber(transaction.timestamp, { min: 0, required: true });
        if (timestamp === null) return null;
        validated.timestamp = timestamp;
      }

      return validated;
    } catch (error) {
      logger.error('VALIDATION', `Transaction validation error: ${error.message}`);
      return null;
    }
  }

  /**
   * CRITICAL: Validate block data with security checks
   * @param {object} block - The block object
   * @returns {object | null} - Validated block or null if invalid
   */
  static validateBlock(block) {
    if (!block || typeof block !== 'object') {
      return null;
    }

    try {
      const validated = {
        index: this.validateNumber(block.index, { min: 0, required: true }),
        timestamp: this.validateNumber(block.timestamp, { min: 0, required: true }),
        previousHash: this.validateHash(block.previousHash, { required: true }),
        nonce: this.validateNumber(block.nonce, { min: 0, required: true }),
        difficulty: this.validateNumber(block.difficulty, { min: 1, required: true }),
        transactions: [],
      };

      if (Object.values(validated).some(v => v === null)) {
        return null;
      }

      // Validate transactions array
      if (Array.isArray(block.transactions)) {
        for (const tx of block.transactions) {
          const validatedTx = this.validateTransaction(tx);
          if (validatedTx) {
            validated.transactions.push(validatedTx);
          }
        }
      }

      return validated;
    } catch (error) {
      logger.error('VALIDATION', `Block validation error: ${error.message}`);
      return null;
    }
  }

  /**
   * SECURE: Safe JSON parsing with validation and error handling
   * @param {string} jsonString - JSON string to parse
   * @param {object} options - Parsing options
   * @returns {object|null} - Parsed object or null if invalid
   */
  static safeJsonParse(jsonString, options = {}) {
    const {
      maxSize = 50 * 1024 * 1024, // 50MB default limit
      allowFunctions = false,
      throwOnError = false
    } = options;

    try {
      // Input validation
      if (typeof jsonString !== 'string') {
        if (throwOnError) throw new Error('Input must be a string');
        return null;
      }

      // Size validation to prevent DoS
      if (jsonString.length > maxSize) {
        if (throwOnError) throw new Error(`JSON string too large: ${jsonString.length} > ${maxSize}`);
        return null;
      }

      // Security check: prevent function execution
      if (!allowFunctions && /\b(function|eval|constructor|prototype|__proto__)\b/i.test(jsonString)) {
        if (throwOnError) throw new Error('JSON contains potentially dangerous content');
        return null;
      }

      // Safe parsing
      const parsed = JSON.parse(jsonString);

      // Additional validation that it's a proper object/array
      if (parsed === null || typeof parsed === 'undefined') {
        if (throwOnError) throw new Error('Parsed JSON is null or undefined');
        return null;
      }

      return parsed;
    } catch (error) {
      logger.error('VALIDATION', `Safe JSON parse error: ${error.message}`);
      if (throwOnError) throw error;
      return null;
    }
  }

  /**
   * SECURE: Safe integer parsing with validation
   * @param {string|number} input - Input to parse as integer
   * @param {object} options - Parsing options
   * @returns {number|null} - Parsed integer or null if invalid
   */
  static safeParseInt(input, options = {}) {
    const {
      min = Number.MIN_SAFE_INTEGER,
      max = Number.MAX_SAFE_INTEGER,
      radix = 10,
      throwOnError = false
    } = options;

    try {
      // Handle null/undefined
      if (input === null || input === undefined || input === '') {
        if (throwOnError) throw new Error('Input is null, undefined, or empty');
        return null;
      }

      // Convert to string for parsing
      const stringInput = String(input).trim();

      // Validate radix
      if (radix < 2 || radix > 36) {
        if (throwOnError) throw new Error(`Invalid radix: ${radix}`);
        return null;
      }

      // Parse integer
      const parsed = parseInt(stringInput, radix);

      // Check if parsing was successful
      if (isNaN(parsed)) {
        if (throwOnError) throw new Error(`Cannot parse '${stringInput}' as integer`);
        return null;
      }

      // Range validation
      if (parsed < min || parsed > max) {
        if (throwOnError) throw new Error(`Parsed integer ${parsed} out of range [${min}, ${max}]`);
        return null;
      }

      return parsed;
    } catch (error) {
      logger.error('VALIDATION', `Safe parseInt error: ${error.message}`);
      if (throwOnError) throw error;
      return null;
    }
  }

  /**
   * SECURE: Safe float parsing with validation
   * @param {string|number} input - Input to parse as float
   * @param {object} options - Parsing options
   * @returns {number|null} - Parsed float or null if invalid
   */
  static safeParseFloat(input, options = {}) {
    const {
      min = Number.MIN_VALUE,
      max = Number.MAX_VALUE,
      allowInfinity = false,
      allowNaN = false,
      throwOnError = false
    } = options;

    try {
      // Handle null/undefined
      if (input === null || input === undefined || input === '') {
        if (throwOnError) throw new Error('Input is null, undefined, or empty');
        return null;
      }

      // Convert to string for parsing
      const stringInput = String(input).trim();

      // Parse float
      const parsed = parseFloat(stringInput);

      // Check if parsing was successful
      if (isNaN(parsed) && !allowNaN) {
        if (throwOnError) throw new Error(`Cannot parse '${stringInput}' as float`);
        return null;
      }

      // Check for infinity
      if (!isFinite(parsed) && !allowInfinity) {
        if (throwOnError) throw new Error(`Parsed float is not finite: ${parsed}`);
        return null;
      }

      // Range validation (only if finite)
      if (isFinite(parsed) && (parsed < min || parsed > max)) {
        if (throwOnError) throw new Error(`Parsed float ${parsed} out of range [${min}, ${max}]`);
        return null;
      }

      return parsed;
    } catch (error) {
      logger.error('VALIDATION', `Safe parseFloat error: ${error.message}`);
      if (throwOnError) throw error;
      return null;
    }
  }
}

module.exports = InputValidator;
