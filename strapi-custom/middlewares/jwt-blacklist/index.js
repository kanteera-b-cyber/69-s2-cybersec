'use strict';

const crypto = require('crypto');
const { isTokenIssuedBeforePasswordChange } = require('../utils/password-audit');

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

module.exports = (config, { strapi }) => {
  const blacklistAction = async (ctx, next) => {
    const authHeader = ctx.request.header.authorization;

    if (!authHeader) {
      return next();
    }

    const parts = authHeader.split(/\s+/);
    if (parts[0].toLowerCase() !== 'bearer' || parts.length !== 2) {
      return next();
    }

    const token = parts[1];
    const tokenHash = hashToken(token);

    const knex = strapi.db.connection;
    const hasTable = await knex.schema.hasTable('jwt_blacklisted_tokens');
    if (!hasTable) {
      return next();
    }

    let decoded;
    try {
      decoded = require('jsonwebtoken').decode(token);
    } catch (err) {
      strapi.log.error('JWT decode failed:', err.message);
      return next();
    }

    if (!decoded || !decoded.id) {
      return next();
    }

    const endpointUserType = ctx.path.startsWith('/admin') ? 'admin' : 'user';

    try {
      const revokedByPasswordChange = await isTokenIssuedBeforePasswordChange(
        strapi,
        decoded.id,
        endpointUserType,
        decoded.iat
      );
      if (revokedByPasswordChange) {
        ctx.unauthorized('Token has been invalidated by a password change');
        return;
      }
    } catch (err) {
      strapi.log.error('Password change check failed:', err.message);
    }

    let claimed = false;
    try {
      const inserted = await knex('jwt_blacklisted_tokens')
        .insert({
          token_hash: tokenHash,
          user_id: decoded.id,
          user_type: 'unknown',
          expires_at: decoded.exp
            ? new Date(decoded.exp * 1000)
            : new Date(Date.now() + 86400000),
        })
        .onConflict('token_hash')
        .ignore()
        .returning('id');

      claimed = inserted.length > 0;
    } catch (err) {
      strapi.log.error('JWT claim failed:', err.message);
    }

    if (!claimed) {
      ctx.unauthorized('Token has already been used and is no longer valid');
      return;
    }

    try {
      await next();
    } catch (err) {
      try {
        await knex('jwt_blacklisted_tokens').where({ token_hash: tokenHash }).del();
      } catch (cleanupErr) {
        strapi.log.error('JWT claim cleanup failed:', cleanupErr.message);
      }
      throw err;
    }

    if (ctx.state && ctx.state.user) {
      try {
        const userType = ctx.state.user.firstname !== undefined ? 'admin' : 'user';
        await knex('jwt_blacklisted_tokens')
          .where({ token_hash: tokenHash })
          .update({ user_type: userType });
      } catch (err) {
        strapi.log.error('JWT user_type update failed:', err.message);
      }
    }
  };

  return blacklistAction;
};