# OpenSphere plugin: samba-ad — 기능 컨테이너(자기 UI 서빙 + 읽기 집계 백엔드).
# D1 승격(2026-07-06): 폴더=컨테이너=신뢰·서명 경계(OpenSphere-plugin-* 규약).
FROM docker.io/library/node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2
ARG OS_MODULE_DESCRIPTOR
ARG OS_MODULE_SIGNATURE
LABEL org.opencontainers.image.title="OpenSphere Samba AD Plugin" \
      org.opencontainers.image.source="https://github.com/opensphere-platform/OpenSphere-plugin-samba-ad" \
      io.opensphere.module.descriptor=$OS_MODULE_DESCRIPTOR \
      io.opensphere.module.descriptor.signature=$OS_MODULE_SIGNATURE \
      io.opensphere.module.descriptor.key-id="opensphere-plugins-v4"
RUN apk upgrade --no-cache \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx
ENV PORT=8080 PLUGIN_DIR=/plugins APP_VERSION=0.1.1-edge.8 \
    NODE_EXTRA_CA_CERTS=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
WORKDIR /app
COPY server.js /app/server.js
COPY ui-shell/ /plugins/
COPY module-package.json module-package.json.sig uipluginpackage.yaml /plugins/
EXPOSE 8080
USER node
CMD ["node", "/app/server.js"]
