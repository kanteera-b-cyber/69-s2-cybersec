'use strict';

const crypto = require('crypto');

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

    try {
      const knex = strapi.db.connection;
      const hasTable = await knex.schema.hasTable('jwt_blacklisted_tokens');
      if (!hasTable) {
        return next();
      }

      const blacklisted = await knex('jwt_blacklisted_tokens')
        .where({ token_hash: tokenHash })
        .first();

      if (blacklisted) {
        ctx.unauthorized('Token has already been used and is no longer valid');
        return;
      }
    } catch (err) {
      strapi.log.error('JWT Blacklist check failed:', err.message);
    }

    await next();

    try {
      const knex = strapi.db.connection;
      const hasTable = await knex.schema.hasTable('jwt_blacklisted_tokens');
      if (!hasTable) return;

      if (ctx.state && ctx.state.user) {
        const jwt = require('jsonwebtoken');
        let secret;

        if (ctx.state.user.firstname !== undefined) {
          secret = strapi.config.get('admin.auth.secret');
        } else {
          secret = strapi.config.get('plugin.users-permissions.jwtSecret');
        }

        const decoded = jwt.decode(token);
        if (decoded && decoded.exp) {
          const expiresAt = new Date(decoded.exp * 1000);
          await knex('jwt_blacklisted_tokens').insert({
            token_hash: tokenHash,
            user_id: ctx.state.user.id,
            user_type: ctx.state.user.firstname !== undefined ? 'admin' : 'user',
            expires_at: expiresAt,
          }).onConflict('token_hash').ignore();
        }
      }
    } catch (err) {
      strapi.log.error('JWT Blacklist insert failed:', err.message);
    }
  };

  return blacklistAction;
};
