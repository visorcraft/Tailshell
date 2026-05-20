FROM node:25.4.0-alpine3.23

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY knexfile.cjs ./knexfile.cjs
COPY migrations ./migrations
COPY src ./src

USER node

EXPOSE 3000

CMD ["node", "src/index.js"]
