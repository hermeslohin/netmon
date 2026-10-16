FROM python:3.12-alpine
WORKDIR /app
# apk upgrade: pick up Alpine security fixes (e.g. zlib) at every rebuild; pip is only needed at build time - remove it
RUN apk upgrade --no-cache && pip install --no-cache-dir pywebpush==2.* \
 && pip uninstall -y pip && rm -rf /root/.cache /usr/local/lib/python3.12/ensurepip
COPY app/ /app/
USER 1000:1000
EXPOSE 8443
HEALTHCHECK --interval=60s --timeout=5s CMD ["python", "-c", "import ssl,urllib.request;urllib.request.urlopen('https://127.0.0.1:8443/healthz',context=ssl._create_unverified_context())"]
CMD ["python", "-u", "/app/server.py"]
