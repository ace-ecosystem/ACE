FROM nginx:alpine

# Default config opens port 80
RUN rm /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/
COPY entrypoint.sh /docker-entrypoint.d/

RUN chmod u+x /docker-entrypoint.d/entrypoint.sh
