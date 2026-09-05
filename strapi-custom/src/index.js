'use strict';

const { ApplicationError, ValidationError } = require('@strapi/utils').errors;

module.exports = {
  register({ strapi }) {
    const adminAuthController = strapi.admin.controllers.authentication;

    adminAuthController.forgotPassword = async (ctx) => {
      const { email } = ctx.request.body || {};

      if (!email || typeof email !== 'string') {
        throw new ApplicationError('Email is required');
      }

      const user = await strapi.query('admin::user').findOne({ where: { email, isActive: true } });

      if (!user) {
        return ctx.send({ ok: true });
      }

      const resetPasswordToken = strapi.admin.services.token.createToken();
      await strapi.admin.services.user.updateById(user.id, { resetPasswordToken });

      strapi.log.warn(
        `[forgot-password] Reset password code for admin ${user.email}: ${resetPasswordToken}`
      );

      ctx.send({
        ok: true,
        code: resetPasswordToken,
        email: user.email,
      });
    };

    adminAuthController.resetPassword = async (ctx) => {
      const { password, resetPasswordToken, code } = ctx.request.body || {};
      const token = resetPasswordToken || code;

      if (!token || typeof token !== 'string') {
        throw new ValidationError('The provided token is invalid');
      }

      if (!password || typeof password !== 'string' || password.length < 6) {
        throw new ValidationError('Please provide a new password with at least 6 characters');
      }

      const user = await strapi
        .query('admin::user')
        .findOne({ where: { resetPasswordToken: token, isActive: true } });

      if (!user) {
        throw new ValidationError('Incorrect code provided');
      }

      const updatedUser = await strapi.admin.services.user.updateById(user.id, {
        password,
        resetPasswordToken: null,
      });

      ctx.send({
        jwt: strapi.admin.services.token.createJwtToken(updatedUser),
        user: strapi.admin.services.user.sanitizeUser(updatedUser),
      });
    };
  },

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