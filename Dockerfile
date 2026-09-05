FROM prawee/strapi

COPY strapi-custom/middlewares/jwt-blacklist/index.js /opt/app/src/middlewares/jwt-blacklist.js
COPY strapi-custom/config/middlewares.js /opt/app/config/middlewares.js
COPY strapi-custom/config/admin.js /opt/app/config/admin.js
COPY strapi-custom/config/api.js /opt/app/config/api.js
COPY strapi-custom/config/server.js /opt/app/config/server.js
COPY strapi-custom/src/extensions/users-permissions/strapi-server.js /opt/app/src/extensions/users-permissions/strapi-server.js
COPY strapi-custom/src/index.js /opt/app/src/index.js
