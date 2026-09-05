module.exports = ({ env }) => ({
  auth: {
    secret: env('ADMIN_JWT_SECRET'),
  },
  rateLimit: {
    enabled: true,
    interval: 60000,
    max: 20,
  },
});
