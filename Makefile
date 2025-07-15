BUCKET_NAME := lacework-alliances
KEY_PREFIX := lacework-aws-security-hub
LAMBDA_PREFIX := lambda/
DATASET := lacework-alliances-prod

#PROFILE ?= alliances-admin
REGION ?= us-west-2

all: build

.PHONY: clean build

clean:
	rm bootstrap || true
	rm main_new.go || true
	rm function.zip || true

build: clean
	buildid=$$(git describe --all --long | cut -d "/" -f 2); \
    	sed -e "s|\$$BUILD|$$buildid|g" -e "s|\$$DATASET|$(HONEY_DATASET)|g" -e "s|\$$HONEYKEY|$(HONEY_KEY)|g" main.go > main_new.go; \
    	GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build -o bootstrap main_new.go
	zip function.zip bootstrap
	@aws --region $(REGION) s3 cp function.zip s3://$(BUCKET_NAME)/$(KEY_PREFIX)/$(LAMBDA_PREFIX) --acl public-read
	rm bootstrap || true
	rm main_new.go || true
	rm function.zip || true




