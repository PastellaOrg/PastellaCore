module.exports = {
  env: {
    node: true,
    es2022: true,
    commonjs: true,
  },
  extends: [
    'eslint:recommended',
    'airbnb-base',
    'plugin:node/recommended',
    'plugin:jsdoc/recommended',
    'prettier', // Must be last to override other configs
  ],
  plugins: [
    'import',
    'node',
    'jsdoc',
    'prettier',
  ],
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
  rules: {
    // === Prettier Integration ===
    'prettier/prettier': 'error', // Show Prettier errors as ESLint errors

    // === Code Quality Rules ===
    'no-console': 'off', // Allow console.log for CLI applications
    'no-debugger': 'warn',
    'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    'no-undef': 'error',
    'no-unreachable': 'error',
    'no-constant-condition': 'error',
    'no-dupe-keys': 'error',
    'no-dupe-args': 'error',
    'no-dupe-class-members': 'error',
    'no-dupe-else-if': 'error',
    'no-empty': 'warn',
    'no-extra-semi': 'error',
    'no-irregular-whitespace': 'error',
    'no-multiple-empty-lines': ['error', { max: 2, maxEOF: 1 }],
    'no-trailing-spaces': 'error',
    'no-unexpected-multiline': 'error',
    'no-unreachable-loop': 'error',
    'no-unsafe-negation': 'error',
    'no-unsafe-optional-chaining': 'error',
    'no-useless-backreference': 'error',
    'no-useless-catch': 'error',
    'no-useless-escape': 'error',
    'no-useless-return': 'error',
    'no-plusplus': 'off', // Disabled to allow ++ and -- operators in loops and counters
    'prefer-const': 'error',
    'prefer-template': 'error',
    'template-curly-spacing': ['error', 'never'],
    'object-curly-spacing': ['error', 'always'],
    'array-bracket-spacing': ['error', 'never'],
    'comma-dangle': 'off', // Disabled to avoid trailing comma issues
    'comma-spacing': ['error', { before: false, after: true }],
    'comma-style': ['error', 'last'],
    'indent': ['error', 2, { SwitchCase: 1 }],
    'linebreak-style': 'off', // Disable line ending checks for cross-platform compatibility
    'quotes': ['error', 'single', { avoidEscape: true, allowTemplateLiterals: true }],
    'semi': ['error', 'always'],
    'space-before-blocks': 'error',
    'space-before-function-paren': ['error', { anonymous: 'always', named: 'never', asyncArrow: 'always' }],
    'space-in-parens': ['error', 'never'],
    'space-infix-ops': 'error',
    'space-unary-ops': ['error', { words: true, nonwords: false }],
    'spaced-comment': ['error', 'always'],
    'keyword-spacing': 'error',
    'key-spacing': ['error', { beforeColon: false, afterColon: true }],
    'brace-style': ['error', '1tbs', { allowSingleLine: true }],
    'camelcase': ['error', { properties: 'never' }],
    'eol-last': 'error',
    'func-call-spacing': ['error', 'never'],
    'function-paren-newline': 'off', // Disabled to allow flexible function parameter formatting
    'max-len': ['warn', { code: 10000, ignoreUrls: true, ignoreStrings: true, ignoreTemplateLiterals: true }],
    'max-lines': ['warn', { max: 10000, skipBlankLines: true, skipComments: true }],
    'max-lines-per-function': ['warn', { max: 200, skipBlankLines: true, skipComments: true }],
    'max-params': ['warn', { max: 10 }],
    'max-classes-per-file': 'off', // Disabled to allow multiple related classes in cryptocurrency files
    'max-depth': ['warn', { max: 4 }],
    'max-nested-callbacks': ['warn', { max: 3 }],
    'complexity': ['warn', { max: 20 }],

    // === Import Rules ===
    'import/order': [
      'error',
      {
        groups: [
          'builtin',
          'external',
          'internal',
          'parent',
          'sibling',
          'index',
        ],
        'newlines-between': 'always',
        alphabetize: { order: 'asc', caseInsensitive: true },
      },
    ],
    'import/no-unresolved': 'off', // Node.js modules
    'import/extensions': ['error', 'ignorePackages'],
    'import/no-extraneous-dependencies': 'off', // Allow dev dependencies in src
    'import/prefer-default-export': 'off',
    'import/no-default-export': 'off',

    // === Node.js Rules ===
    'node/no-unsupported-features/es-syntax': 'off',
    'node/no-missing-import': 'off',
    'node/no-unpublished-import': 'off',
    'node/no-unpublished-require': 'off',
    'node/no-extraneous-require': 'off',
    'node/no-missing-require': 'off',
    'node/no-process-exit': 'warn',
    'node/no-callback-literal': 'error',
    'node/callback-return': 'error',
    'node/handle-callback-err': 'error',
    'node/no-new-require': 'error',
    'node/no-path-concat': 'error',
    'node/no-sync': 'warn',
    'node/prefer-global/buffer': 'error',
    'node/prefer-global/console': 'error',
    'node/prefer-global/process': 'error',
    'node/prefer-global/url-search-params': 'error',
    'node/prefer-global/url': 'error',
    'node/prefer-promises/dns': 'error',
    'node/prefer-promises/fs': 'error',

    // === Security Rules ===
    'no-eval': 'error',
    'no-implied-eval': 'error',
    'no-new-func': 'error',
    'no-script-url': 'error',

    // === JSDoc Rules ===
    'jsdoc/require-jsdoc': [
      'warn',
      {
        publicOnly: false,
        require: {
          FunctionDeclaration: true,
          MethodDefinition: true,
          ClassDeclaration: true,
        },
        contexts: [
          'ExportNamedDeclaration',
          'ExportDefaultDeclaration',
        ],
      },
    ],
    'jsdoc/require-param': 'warn',
    'jsdoc/require-param-description': 'off', // Disabled to reduce JSDoc requirements
    'jsdoc/require-param-name': 'warn',
    'jsdoc/require-param-type': 'off', // Disabled to reduce JSDoc requirements
    'jsdoc/require-returns': 'off',
    'jsdoc/require-returns-description': 'off',
    'jsdoc/require-returns-type': 'off',
    'jsdoc/valid-types': 'warn',
    'jsdoc/check-tag-names': 'warn',
    'jsdoc/check-param-names': 'warn',
    'jsdoc/check-types': 'warn',
    'jsdoc/no-undefined-types': 'off',
    'jsdoc/require-description': 'off',
    'jsdoc/require-example': 'off',

    // === Cryptocurrency Specific Rules ===
    'no-magic-numbers': 'off', // Disabled to allow common numbers like HTTP status codes, port numbers, etc.
    'no-bitwise': 'off', // Allow bitwise operations for cryptographic functions
    'no-param-reassign': ['error', { props: false }], // Allow parameter property modification
    'no-underscore-dangle': 'off', // Allow underscore prefix for private methods
    'class-methods-use-this': 'off', // Allow static methods
    'no-restricted-syntax': 'off', // Disabled to allow various loop constructs and syntax patterns

    // === Async/Await Rules ===
    'require-await': 'error',
    'no-async-promise-executor': 'error',
    'no-await-in-loop': 'off', // Disabled to allow await in loops for GPU operations
    'no-promise-executor-return': 'error',
    'prefer-promise-reject-errors': 'error',

    // === Error Handling Rules ===
    'no-throw-literal': 'error',
    'prefer-promise-reject-errors': 'error',
    'no-return-await': 'error',
    'require-await': 'error',

    // === Function and Method Rules ===
    'consistent-return': 'off', // Disabled for Express.js route handlers that don't need return values

    // === Performance Rules ===
    'no-loop-func': 'error',
    'no-new-func': 'error',
    'no-eval': 'error',
    'no-implied-eval': 'error',
    'no-new-wrappers': 'error',
    'no-script-url': 'error',
    'no-sequences': 'error',
    'no-throw-literal': 'error',
    'no-unused-expressions': 'error',
    'no-useless-call': 'error',
    'no-useless-concat': 'error',
    'no-useless-return': 'error',
    'prefer-const': 'error',
    'prefer-spread': 'error',
    'prefer-template': 'error',
  },
  overrides: [
    {
      // CLI files can use console.log
      files: ['src/cli/**/*.js', 'src/index.js'],
      rules: {
        'no-console': 'off',
        'max-lines-per-function': 'off',
        'complexity': 'off',
      },
    },
    {
      // Test files have different rules
      files: ['**/*.test.js', '**/*.spec.js', 'test/**/*.js'],
      env: {
        jest: true,
      },
      rules: {
        'no-console': 'off',
        'jsdoc/require-jsdoc': 'off',
        'security/detect-non-literal-require': 'off',
      },
    },
    {
      // Configuration files
      files: ['*.config.js', '*.config.mjs'],
      rules: {
        'jsdoc/require-jsdoc': 'off',
        'import/no-commonjs': 'off',
      },
    },
  ],
  ignorePatterns: [
    'node_modules/',
    'dist/',
    'build/',
    'coverage/',
    '*.min.js',
    'data/',
    'config.json',
    'ESLINT_README.md',
  ],
  settings: {
    'import/resolver': {
      node: {
        extensions: ['.js', '.json'],
      },
    },
  },
};
