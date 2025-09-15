/**
 * Transaction tags for categorizing different types of transactions
 *
 * System Tags (reserved for internal use):
 * - STAKING: For staking-related transactions
 * - GOVERNANCE: For governance/proposal transactions
 * - COINBASE: For mining rewards (automatically applied)
 * - PREMINE: For genesis block premine (automatically applied)
 * - CONTRACT: For smart contract operations (automatically applied)
 *
 * User Tags:
 * - TRANSACTION: For regular user transactions (only tag users can create)
 */
const TRANSACTION_TAGS = {
  STAKING: 'STAKING',
  GOVERNANCE: 'GOVERNANCE',
  COINBASE: 'COINBASE',
  TRANSACTION: 'TRANSACTION',
  PREMINE: 'PREMINE',
  CONTRACT: 'CONTRACT',
};

module.exports = {
  TRANSACTION_TAGS,
};
