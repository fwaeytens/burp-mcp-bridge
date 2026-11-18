# Burp Suite Community runner for the integration suite.
#
# The Burp Community jar and the built extension jar are NOT baked into the
# image. They are mounted read-only at runtime (see docker-compose.yml): the jar
# is 685 MB and licence-bound, and the extension changes every build. Keeping
# them out of the image makes rebuilds instant and the image redistributable.
#
# Temurin 21 is PortSwigger's stated minimum JRE and multi-arch (arm64 + amd64).
FROM eclipse-temurin:21-jre-jammy

# Xvfb: headless X server. fluxbox: minimal WM so the wizard window takes focus.
# xdotool + x11-utils: drive/inspect the wizard. fonts: Swing needs real fonts.
# scrot: screenshot the virtual display when the wizard does not get dismissed
#   (docker compose exec burp scrot /tmp/s.png) — the only way to see why.
RUN apt-get update && apt-get install -y --no-install-recommends \
      xvfb \
      fluxbox \
      xdotool \
      x11-utils \
      scrot \
      fontconfig \
      fonts-dejavu-core \
      procps \
      curl \
    && rm -rf /var/lib/apt/lists/*

ENV BURP_HOME=/burp-home
ENV DISPLAY=:99

# Burp config seeds: user-config registers the extension (its path is rendered
# from @EXT_JAR@ at runtime), project-config opens the proxy on all interfaces.
COPY user-config.json project-config.json /config/

COPY entrypoint.sh delete-history-row.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/delete-history-row.sh

EXPOSE 8080 8081

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
