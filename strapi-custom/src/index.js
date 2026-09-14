'use strict';

const { ApplicationError, ValidationError } = require('@strapi/utils').errors;
const { assertStrongPassword } = require('./utils/password');
const {
  issueResetToken,
  verifyResetToken,
  cleanExpiredResetTokens,
} = require('./utils/reset-token');

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

      const resetPasswordToken = await issueResetToken(strapi, user.id, 'admin');

      strapi.log.info('[forgot-password] Reset password token has been set for the admin account');

      if (process.env.NODE_ENV !== 'production') {
        ctx.send({ ok: true, code: resetPasswordToken });
      } else {
        ctx.send({ ok: true });
      }
    };

    adminAuthController.resetPassword = async (ctx) => {
      const { password, passwordConfirmation, resetPasswordToken, code } = ctx.request.body || {};
      const token = resetPasswordToken || code;

      if (!token || typeof token !== 'string') {
        throw new ValidationError('The provided token is invalid');
      }

      if (password !== passwordConfirmation) {
        throw new ValidationError('Password confirmation does not match');
      }

      assertStrongPassword(password);

      const tokenRow = await verifyResetToken(strapi, token, 'admin');
      if (!tokenRow) {
        throw new ValidationError('Incorrect or expired code provided');
      }

      const user = await strapi
        .query('admin::user')
        .findOne({ where: { id: tokenRow.user_id, isActive: true } });

      if (!user) {
        throw new ValidationError('Incorrect or expired code provided');
      }

      const updatedUser = await strapi.admin.services.user.updateById(user.id, {
        password,
      });

      ctx.send({
        jwt: strapi.admin.services.token.createJwtToken(updatedUser),
        user: strapi.admin.services.user.sanitizeUser(updatedUser),
      });
    };

    const defaultRegisterAdmin = strapi.admin.controllers.authentication.registerAdmin;
    strapi.admin.controllers.authentication.registerAdmin = async (ctx) => {
      const { password } = ctx.request.body || {};
      assertStrongPassword(password);
      return defaultRegisterAdmin(ctx);
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

    const hasResetTable = await knex.schema.hasTable('password_reset_tokens');
    if (!hasResetTable) {
      await knex.schema.createTable('password_reset_tokens', (table) => {
        table.increments('id').primary();
        table.string('token_hash', 64).notNullable().unique();
        table.integer('user_id').notNullable();
        table.string('user_type', 10).notNullable();
        table.timestamp('expires_at').notNullable();
        table.timestamp('created_at').defaultTo(knex.fn.now());
      });
      strapi.log.info('Created password_reset_tokens table');
    }

    const resetDeleted = await cleanExpiredResetTokens(strapi);
    if (resetDeleted > 0) {
      strapi.log.info(`Cleaned up ${resetDeleted} expired reset tokens`);
    }
  },
};