FROM node:24.11.1-alpine3.22
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY AnchorRegistry.sol compile.mjs deploy.mjs anchor.mjs verify.mjs bootstrap.mjs ./
CMD ["node", "deploy.mjs"]
