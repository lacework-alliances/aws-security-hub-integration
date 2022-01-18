BUCKET_NAME := lacework-alliances
KEY_PREFIX := lacework-aws-security-hub
LAMBDA_PREFIX := lambda/
DATASET := lacework-alliances-dev

PROFILE ?= ct
REGION ?= us-west-2

all: build

.PHONY: clean build

clean:
	rm main || true
	rm function.zip || true

build: clean
	GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build -o main *.go
	zip function.zip main
	@aws --region $(REGION) s3 cp function.zip s3://$(BUCKET_NAME)/$(KEY_PREFIX)/$(LAMBDA_PREFIX) --acl public-read
	rm main || true
	rm function.zip || true




