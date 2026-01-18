FROM node:20-alpine

WORKDIR /app

# Install tar (required for archive creation)
RUN apk add --no-cache tar

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 3017

CMD ["node", "server.js"]
