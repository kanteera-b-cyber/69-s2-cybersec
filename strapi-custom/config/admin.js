module.exports = ({ env }) => ({
  auth: {
    secret: env('ADMIN_JWT_SECRET'),
  },
  apiToken: {
    salt: env('API_TOKEN_SALT'),
  },
  rateLimit: {
    enabled: true,
    interval: 60000,
    max: 20,
  },
});
