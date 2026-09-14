'use strict';

const { sanitize } = require('@strapi/utils');
const { ApplicationError, ValidationError } = require('@strapi/utils').errors;
const { assertStrongPassword } = require('../../utils/password');
const { issueResetToken, verifyResetToken } = require('../../utils/reset-token');
const { recordPasswordChange } = require('../../utils/password-audit');

const sanitizeUser = (user, ctx) => {
  const userSchema = strapi.getModel('plugin::users-permissions.user');
  return sanitize.contentAPI.output(user, userSchema, { auth: ctx.state.auth });
};

module.exports = (plugin) => {
  const { auth } = plugin.controllers;

  auth.forgotPassword = async (ctx) => {
    const { email } = ctx.request.body || {};

    if (!email || typeof email !== 'string') {
      throw new ApplicationError('Provided email is invalid');
    }

    const user = await strapi.query('plugin::users-permissions.user').findOne({
      where: { email: email.toLowerCase() },
    });

    if (!user || user.blocked) {
      return ctx.send({ ok: true });
    }

    const resetPasswordToken = await issueResetToken(strapi, user.id, 'user');

    strapi.log.info('[forgot-password] Reset password token has been set for the user account');

    if (process.env.NODE_ENV !== 'production') {
      ctx.send({ ok: true, code: resetPasswordToken });
    } else {
      ctx.send({ ok: true });
    }
  };

  auth.resetPassword = async (ctx) => {
    const { password, passwordConfirmation, resetPasswordToken, code } = ctx.request.body || {};
    const token = resetPasswordToken || code;

    if (!token || typeof token !== 'string') {
      throw new ValidationError('The provided token is invalid');
    }

    if (password !== passwordConfirmation) {
      throw new ValidationError('Password confirmation does not match');
    }

    assertStrongPassword(password);

    const tokenRow = await verifyResetToken(strapi, token, 'user');
    if (!tokenRow) {
      throw new ValidationError('Incorrect or expired code provided');
    }

    const user = await strapi.query('plugin::users-permissions.user').findOne({
      where: { id: tokenRow.user_id },
    });

    if (!user) {
      throw new ValidationError('Incorrect or expired code provided');
    }

    await strapi
      .service('plugin::users-permissions.user')
      .edit(user.id, { password });

    await recordPasswordChange(strapi, user.id, 'user');

    const jwt = strapi.plugin('users-permissions').service('jwt').issue({ id: user.id });

    ctx.send({
      jwt,
      user: await sanitizeUser(user, ctx),
    });
  };

  const defaultRegister = auth.register;
  auth.register = async (ctx) => {
    const pluginStore = strapi.store({ type: 'plugin', name: 'users-permissions' });
    const advanced = await pluginStore.get({ key: 'advanced' });

    if (!advanced || !advanced.allow_register) {
      return ctx.badRequest('Register action is currently disabled.');
    }

    const { password } = ctx.request.body || {};
    assertStrongPassword(password);
    return defaultRegister(ctx);
  };

  if (auth.changePassword) {
    const defaultChangePassword = auth.changePassword;
    auth.changePassword = async (ctx) => {
      const { password } = ctx.request.body || {};
      assertStrongPassword(password);

      const result = await defaultChangePassword(ctx);

      if (ctx.state && ctx.state.user) {
        await recordPasswordChange(strapi, ctx.state.user.id, 'user');
      }

      return result;
    };
  }

  return plugin;
};