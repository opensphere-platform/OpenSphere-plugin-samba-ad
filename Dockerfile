# OpenSphere plugin: samba-ad — 기능 컨테이너(자기 UI 서빙 + 읽기 집계 백엔드).
# D1 승격(2026-07-06): 폴더=컨테이너=신뢰·서명 경계(OpenSphere-plugin-* 규약).
FROM docker.io/library/node:22-alpine
ENV PORT=8080 PLUGIN_DIR=/plugins APP_VERSION=0.1.0 \
    NODE_EXTRA_CA_CERTS=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
WORKDIR /app
COPY server.js /app/server.js
COPY ui-shell/ /plugins/
EXPOSE 8080
USER node
CMD ["node", "/app/server.js"]
