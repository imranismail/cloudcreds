FROM golang:1.13

WORKDIR /go/src/github.com/imranismail/cloudcreds
COPY . .

RUN go get -d -v ./...
RUN go install -v ./...

CMD ["cloudcreds"]