FROM golang:alpine
RUN apk add --no-cache unbound-dev build-base
COPY . /dane
WORKDIR /dane/cmd/letsdane
RUN go build -tags unbound

FROM alpine:latest
RUN apk add --no-cache unbound-dev 
COPY --from=0 /dane /dane
WORKDIR /dane/cmd/letsdane
EXPOSE 8080
ENTRYPOINT ["./letsdane"]
