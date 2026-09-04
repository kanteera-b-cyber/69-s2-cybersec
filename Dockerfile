FROM prawee/strapi

COPY strapi-custom/middlewares/jwt-blacklist/index.js /opt/app/src/middlewares/jwt-blacklist.js
COPY strapi-custom/config/middlewares.js /opt/app/config/middlewares.js
COPY strapi-custom/src/index.js /opt/app/src/index.js
