########################################
# Stage 1 – Install dependencies
########################################
FROM node:20-alpine AS deps
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

########################################
# Stage 2 – Build
########################################
FROM node:20-alpine AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production

ARG SITE_URL
ENV NEXT_PUBLIC_SITE_URL=$SITE_URL

RUN npm run build

########################################
# Stage 3 – Runtime (nginx + Node standalone)
########################################
FROM node:20-alpine AS runner

RUN apk add --no-cache nginx supervisor \
    && mkdir -p /run/nginx /var/log/nginx /var/lib/nginx/tmp \
    && addgroup -S app && adduser -S app -G app

WORKDIR /app

# Next.js standalone server
COPY --from=builder --chown=app:app /app/.next/standalone ./
# Static assets served directly by nginx
COPY --from=builder --chown=app:app /app/.next/static ./.next/static
# Public folder
COPY --from=builder --chown=app:app /app/public ./public

COPY nginx.conf /etc/nginx/nginx.conf
COPY supervisord.conf /etc/supervisord.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost/api/contact || exit 1

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
