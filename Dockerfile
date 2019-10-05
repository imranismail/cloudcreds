FROM golang:1.13

WORKDIR /go/src/github.com/imranismail/cloudcreds

COPY . .

RUN go install

FROM golang:1.13

COPY --from=0 /go/bin/cloudcreds /go/bin

CMD ["cloudcreds"]