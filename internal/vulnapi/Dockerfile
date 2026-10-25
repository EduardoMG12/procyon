# Build from the repository root:
#   docker build -f internal/vulnapi/Dockerfile .
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY internal/vulnapi ./internal/vulnapi
RUN CGO_ENABLED=0 go build -o /vulnapi ./internal/vulnapi/cmd/vulnapi

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /vulnapi /vulnapi
EXPOSE 8080
HEALTHCHECK --interval=2s --timeout=2s --retries=15 CMD ["/vulnapi", "-healthcheck"]
ENTRYPOINT ["/vulnapi"]
