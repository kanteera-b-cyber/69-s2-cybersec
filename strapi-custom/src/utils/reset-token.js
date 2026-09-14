'use strict';

const crypto = require('crypto');

const RESET_TOKEN_TTL_MS = 15 * 60 * 1000;

const hashToken = (token) => crypto.createHash('sha256').update(token).digest('hex');

const generateResetToken = () => crypto.randomBytes(32).toString('hex');

const issueResetToken = async (strapi, userId, userType) => {
  const token = generateResetToken();
  await strapi.db.connection('password_reset_tokens').insert({
    token_hash: hashToken(token),
    user_id: userId,
    user_type: userType,
    expires_at: new Date(Date.now() + RESET_TOKEN_TTL_MS),
  });
  return token;
};

const verifyResetToken = async (strapi, token, userType) => {
  if (!token || typeof token !== 'string') {
    return null;
  }

  const knex = strapi.db.connection;

  const row = await knex('password_reset_tokens')
    .where({ token_hash: hashToken(token), user_type: userType })
    .first();

  if (!row) {
    return null;
  }

  await knex('password_reset_tokens').where({ id: row.id }).del();

  if (new Date(row.expires_at) < new Date()) {
    return null;
  }

  return row;
};

const cleanExpiredResetTokens = async (strapi) => {
  const knex = strapi.db.connection;
  const hasTable = await knex.schema.hasTable('password_reset_tokens');
  if (!hasTable) {
    return 0;
  }
  return knex('password_reset_tokens').where('expires_at', '<', new Date()).del();
};

module.exports = {
  RESET_TOKEN_TTL_MS,
  hashToken,
  generateResetToken,
  issueResetToken,
  verifyResetToken,
  cleanExpiredResetTokens,
};