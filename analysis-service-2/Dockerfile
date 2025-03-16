FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

EXPOSE 3001

# Set environment variables with default empty values
# These should be overridden when running the container
ENV VIRUSTOTAL_API_KEY=""
ENV ABUSEIPDB_API_KEY=""
ENV REDIS_HOST="redis"
ENV REDIS_PORT="6379"

CMD ["npm", "start"] 