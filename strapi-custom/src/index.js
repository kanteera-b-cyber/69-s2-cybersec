'use strict';

module.exports = {
  register(/*{ strapi }*/) {},

  async bootstrap({ strapi }) {
    const knex = strapi.db.connection;

    const hasTable = await knex.schema.hasTable('jwt_blacklisted_tokens');
    if (!hasTable) {
      await knex.schema.createTable('jwt_blacklisted_tokens', (table) => {
        table.increments('id').primary();
        table.string('token_hash', 64).notNullable().unique();
        table.integer('user_id').notNullable();
        table.string('user_type', 10).notNullable();
        table.timestamp('expires_at').notNullable();
        table.timestamp('created_at').defaultTo(knex.fn.now());
      });
      strapi.log.info('Created jwt_blacklisted_tokens table');
    }

    const deleted = await knex('jwt_blacklisted_tokens')
      .where('expires_at', '<', new Date())
      .del();
    if (deleted > 0) {
      strapi.log.info(`Cleaned up ${deleted} expired blacklisted tokens`);
    }
  },
};
