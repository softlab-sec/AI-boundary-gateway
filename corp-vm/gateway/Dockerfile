FROM mitmproxy/mitmproxy:11.1.3
USER root
RUN pip install --no-cache-dir pyyaml requests
RUN mkdir -p /var/log/boundary /var/lib/boundary
COPY addons /addons
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
