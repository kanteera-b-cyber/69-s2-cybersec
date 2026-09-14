module.exports = [
  'strapi::logger',
  'strapi::errors',
  'strapi::security',
  'strapi::cors',
  'strapi::poweredBy',
  'strapi::query',
  'strapi::body',
  'strapi::session',
  'strapi::favicon',
  'strapi::public',
  {
    name: 'global::jwt-blacklist',
    config: {},
  },
  {
    name: 'global::rate-limit',
    config: {
      windowMs: 60 * 1000,
      max: 10,
    },
  },
];
