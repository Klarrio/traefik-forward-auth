FROM alpine:3.9.3

# Now we DO need these, for the auto-labeling of the image
ARG BUILD_DATE
ARG VCS_REF

# Good docker practice, plus we get microbadger badges
LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vcs-url="https://gitlab.com/Klarrio/dev/tool/traefik-forward-auth.git" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.schema-version="2.2-r1"

# Copy into scratch container
RUN apk update && apk add ca-certificates tzdata && rm -rf /var/cache/apk/*
RUN update-ca-certificates
COPY traefik-forward-auth-linux /go/bin/
ENTRYPOINT ["./traefik-forward-auth-linux"]
