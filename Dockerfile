FROM golang:1.9.1-alpine

ADD . /go/src/app

RUN go get app
RUN go install app

RUN /go/bin/app