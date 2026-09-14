'use strict';

const TABLE = 'rate_limit_attempts';

const DEFAULT_PATHS = [
  '/api/auth/local',
  '/api/auth/local/register',
  '/api/auth/forgot-password',
  '/api/auth/reset-password',
  '/api/auth/change-password',
];

module.exports = (config, { strapi }) => {
  const windowMs = config.windowMs || 60 * 1000;
  const max = config.max === undefined ? 10 : config.max;
  const paths = (config.paths || DEFAULT_PATHS).map((p) => String(p));

  const rateLimitAction = async (ctx, next) => {
    const pathname = ctx.path;

    const isProtected = paths.some(
      (p) => pathname === p || pathname.startsWith(`${p}/`)
    );
    if (!isProtected) {
      return next();
    }

    const ip =
      ctx.request.ip ||
      (ctx.request.socket && ctx.request.socket.remoteAddress) ||
      'unknown';

    const knex = strapi.db.connection;
    const hasTable = await knex.schema.hasTable(TABLE);
    if (!hasTable) {
      return next();
    }

    const rateKey = `${ip}:${pathname}`;
    const since = new Date(Date.now() - windowMs);

    let attempts = 0;
    try {
      const rows = await knex(TABLE)
        .where({ rate_key: rateKey })
        .andWhere('attempt_at', '>', since)
        .count({ total: '*' });
      attempts = Number(rows[0] && rows[0].total) || 0;
    } catch (err) {
      strapi.log.error('Rate limit check failed:', err.message);
      return next();
    }

    if (attempts >= max) {
      ctx.set('Retry-After', String(Math.ceil(windowMs / 1000)));
      ctx.throw(429, 'Too many requests');
    }

    try {
      await knex(TABLE).insert({ rate_key: rateKey, attempt_at: new Date() });
    } catch (err) {
      strapi.log.error('Rate limit record failed:', err.message);
    }

    return next();
  };

  return rateLimitAction;
};