FROM node:20-alpine AS build

WORKDIR /web

COPY web/package*.json ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

COPY web/ ./

# Build-time defaults only. The published image is generic and takes its API
# address from the environment at container start (see docker-entrypoint.sh),
# so these are left empty in CI.
ARG REACT_APP_API_URL=
ARG REACT_APP_WS_URL=
ARG APP_PORT=
ARG REACT_APP_API_PORT=

ENV REACT_APP_API_URL=${REACT_APP_API_URL}
ENV REACT_APP_WS_URL=${REACT_APP_WS_URL}
ENV APP_PORT=${APP_PORT}
ENV REACT_APP_API_PORT=${REACT_APP_API_PORT}

RUN npm run build

FROM nginx:1.27-alpine

COPY docker/ui/nginx.conf /etc/nginx/conf.d/default.conf
COPY docker/ui/docker-entrypoint.sh /docker-entrypoint-stackdog.sh
COPY --from=build /web/dist /usr/share/nginx/html

RUN chmod +x /docker-entrypoint-stackdog.sh

EXPOSE 80

ENTRYPOINT ["/docker-entrypoint-stackdog.sh"]
CMD ["nginx", "-g", "daemon off;"]
