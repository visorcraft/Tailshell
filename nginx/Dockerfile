FROM node:25.4.0-alpine3.23 AS ui-build

WORKDIR /app/ui

COPY ui/package.json ui/package-lock.json ./
RUN npm ci

# Precompress build output for brotli_static serving.
RUN apk add --no-cache brotli

# Cache bust: pass --build-arg UI_CACHEBUST=$(date +%s) to force UI rebuild
ARG UI_CACHEBUST=1
COPY ui/ ./
RUN npm run build && \
  find dist -type f \( \
    -name '*.html' -o \
    -name '*.css' -o \
    -name '*.js' -o \
    -name '*.json' -o \
    -name '*.svg' -o \
    -name '*.map' \
  \) -exec brotli -f -k -q 11 {} \;


FROM alpine:3.23 AS brotli-build

ARG NGINX_VERSION=1.29.4
ARG NGX_BROTLI_REF=a71f9312c2deb28875acc7bacfdd5695a111aa53

RUN apk add --no-cache \
  build-base \
  cmake \
  curl \
  git \
  linux-headers \
  openssl-dev \
  pcre2-dev \
  zlib-dev

WORKDIR /tmp

RUN curl -fsSL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" | tar -xz
RUN git clone https://github.com/google/ngx_brotli.git
WORKDIR /tmp/ngx_brotli
RUN git checkout "${NGX_BROTLI_REF}" && git submodule update --init --recursive --jobs 8

WORKDIR /tmp/ngx_brotli/deps/brotli
RUN mkdir -p out && cd out && \
  cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON .. && \
  cmake --build . --config Release

WORKDIR "/tmp/nginx-${NGINX_VERSION}"
RUN ./configure --with-compat --add-dynamic-module=../ngx_brotli
RUN make modules
RUN mkdir -p /out && cp objs/ngx_http_brotli*_module.so /out/


FROM nginx:1.29.4-alpine

COPY nginx/nginx.conf /etc/nginx/nginx.conf

# Compression modules (brotli)
COPY --from=brotli-build /out/ngx_http_brotli_filter_module.so /usr/lib/nginx/modules/
COPY --from=brotli-build /out/ngx_http_brotli_static_module.so /usr/lib/nginx/modules/

# Main UI (built assets)
COPY --from=ui-build /app/ui/dist/ /usr/share/nginx/html/

# Auth pages + shared assets
COPY nginx/login.html /usr/share/nginx/html/login.html
COPY nginx/login.js /usr/share/nginx/html/login.js
COPY nginx/login.css /usr/share/nginx/html/login.css
COPY nginx/change-password.html /usr/share/nginx/html/change-password.html
COPY nginx/change-password.js /usr/share/nginx/html/change-password.js
COPY nginx/change-password.css /usr/share/nginx/html/change-password.css
COPY nginx/invite.html /usr/share/nginx/html/invite.html
COPY nginx/invite.js /usr/share/nginx/html/invite.js
COPY nginx/invite.css /usr/share/nginx/html/invite.css
COPY nginx/reset-password.html /usr/share/nginx/html/reset-password.html
COPY nginx/reset-password.js /usr/share/nginx/html/reset-password.js
COPY nginx/reset-password.css /usr/share/nginx/html/reset-password.css
COPY nginx/favicon.svg /usr/share/nginx/html/favicon.svg
