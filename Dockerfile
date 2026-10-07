# Single-server production image: builds React client, builds Express API, then serves both.
FROM node:22-alpine AS client-build
WORKDIR /app/client
COPY client/package*.json ./
RUN npm install --no-audit --no-fund
COPY client/ ./
RUN npm run build

FROM node:22-alpine AS server-build
WORKDIR /app/server
COPY server/package*.json ./
RUN npm install --no-audit --no-fund
COPY server/ ./
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=server-build /app/server/node_modules ./server/node_modules
COPY --from=server-build /app/server/dist ./server/dist
COPY --from=server-build /app/server/sql ./server/sql
COPY --from=server-build /app/server/package.json ./server/package.json
COPY --from=client-build /app/client/dist ./client/dist
EXPOSE 4000
CMD ["node","server/dist/index.js"]
