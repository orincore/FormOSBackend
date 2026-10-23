FROM node:20-bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ghostscript \
    graphicsmagick \
    tesseract-ocr \
    chromium \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
ENV PUPPETEER_SKIP_DOWNLOAD=true
RUN npm ci --omit=dev

COPY . .

ENV PUPPETEER_SKIP_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

RUN mkdir -p uploads

EXPOSE 5000

CMD ["npm", "start"]
