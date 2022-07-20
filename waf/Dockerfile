ARG GOVERSION=1.17

FROM golang:${GOVERSION}-alpine AS build

WORKDIR /go/src/waf

# wizard.sh requires GNU coreutils
RUN apk add --no-cache git libc-dev bash
RUN wget https://raw.githubusercontent.com/jptosso/coraza-waf/v2/master/coraza.conf-recommended
RUN git clone https://github.com/coreruleset/coreruleset
COPY . .

RUN go install && go build

FROM alpine:latest
RUN apk add --no-cache --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community bash
RUN mkdir /src
WORKDIR /src
COPY --from=build /go/src/waf/waf /src/waf
COPY ./coraza.conf /src/coraza.conf
COPY --from=build /go/src/waf/coreruleset /src/coreruleset
ENTRYPOINT [ "/src/waf" ]
