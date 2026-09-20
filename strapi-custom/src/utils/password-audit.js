'use strict';

const recordPasswordChange = async (strapi, userId, userType) => {
  try {
    const knex = strapi.db.connection;
    const hasTable = await knex.schema.hasTable('user_password_changes');
    if (!hasTable) {
      return;
    }
    await knex('user_password_changes').insert({
      user_id: userId,
      user_type: userType,
      changed_at: new Date(),
    });
  } catch (err) {
    strapi.log.error('Failed to record password change:', err.message);
  }
};

const isTokenIssuedBeforePasswordChange = async (strapi, userId, userType, iatSeconds) => {
  const knex = strapi.db.connection;

  const hasTable = await knex.schema.hasTable('user_password_changes');
  if (!hasTable || !userId || !userType || !iatSeconds) {
    return false;
  }

  const latestChange = await knex('user_password_changes')
    .where({ user_id: userId, user_type: userType })
    .orderBy('changed_at', 'desc')
    .first();

  if (!latestChange) {
    return false;
  }

  return new Date(iatSeconds * 1000) < new Date(latestChange.changed_at);
};

module.exports = { recordPasswordChange, isTokenIssuedBeforePasswordChange };