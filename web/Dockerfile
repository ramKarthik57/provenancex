FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install

COPY . .
RUN npm run build

FROM nginx:alpine AS runner
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 3000

# Simple Nginx configuration for SPA routing on port 3000
RUN printf 'server {\n listen 3000;\n location / {\n  root /usr/share/nginx/html;\n  index index.html index.htm;\n  try_files $uri $uri/ /index.html;\n }\n}\n' > /etc/nginx/conf.d/default.conf

CMD ["nginx", "-g", "daemon off;"]
