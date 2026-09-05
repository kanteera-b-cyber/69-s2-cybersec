'use strict';

const crypto = require('crypto');
const { sanitize } = require('@strapi/utils');
const { ApplicationError, ValidationError } = require('@strapi/utils').errors;

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

    const resetPasswordToken = crypto.randomBytes(64).toString('hex');

    await strapi
      .service('plugin::users-permissions.user')
      .edit(user.id, { resetPasswordToken });

    strapi.log.warn(
      `[forgot-password] Reset password code for ${user.email}: ${resetPasswordToken}`
    );

    ctx.send({
      ok: true,
      code: resetPasswordToken,
      email: user.email,
    });
  };

  auth.resetPassword = async (ctx) => {
    const { password, resetPasswordToken, code } = ctx.request.body || {};
    const token = resetPasswordToken || code;

    if (!token || typeof token !== 'string') {
      throw new ValidationError('The provided token is invalid');
    }

    if (!password || typeof password !== 'string' || password.length < 6) {
      throw new ValidationError('Please provide a new password with at least 6 characters');
    }

    const user = await strapi.query('plugin::users-permissions.user').findOne({
      where: { resetPasswordToken: token },
    });

    if (!user) {
      throw new ValidationError('Incorrect code provided');
    }

    await strapi
      .service('plugin::users-permissions.user')
      .edit(user.id, { resetPasswordToken: null, password });

    const jwt = strapi.plugin('users-permissions').service('jwt').issue({ id: user.id });

    ctx.send({
      jwt,
      user: await sanitizeUser(user, ctx),
    });
  };

  return plugin;
};