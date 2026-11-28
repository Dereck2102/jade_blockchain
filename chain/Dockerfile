FROM node:24.11.1-alpine3.22
WORKDIR /app
RUN mkdir -p /data /chain && chown -R 1000:1000 /app /data /chain
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY AnchorRegistry.sol lib.mjs compile.mjs deploy.mjs anchor.mjs verify.mjs bootstrap.mjs ./
USER 1000:1000
CMD ["node", "deploy.mjs"]
