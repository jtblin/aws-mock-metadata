VERSION_VAR := main.VERSION
REPO_VERSION := $(shell git describe --always --dirty --tags)
GOBUILD_VERSION_ARGS := -ldflags "-X $(VERSION_VAR)=$(REPO_VERSION)"
GIT_HASH := $(shell git rev-parse --short HEAD)

include .env

setup:
	go get -v
	go get -v -u github.com/githubnemo/CompileDaemon
	go get -v -u github.com/alecthomas/gometalinter
	gometalinter --install --update

build: *.go
	gofmt -w=true .
	go build -o bin/aws-mock-metadata -x $(GOBUILD_VERSION_ARGS) github.com/jtblin/aws-mock-metadata

test: check
	go test

junit-test: build
	go get github.com/jstemmer/go-junit-report
	go test -v | go-junit-report > test-report.xml

check: build
	gometalinter ./...

watch:
	CompileDaemon -color=true -build "make test"

commit-hook:
	cp dev/commit-hook.sh .git/hooks/pre-commit

cross:
	 CGO_ENABLED=0 GOOS=linux go build -ldflags "-s" -a -installsuffix cgo -o bin/aws-mock-metadata-linux .

docker: cross
	 docker build -t jtblin/aws-mock-metadata:$(GIT_HASH) .

version:
	@echo $(REPO_VERSION)

run:
	AWS_ACCESS_KEY_ID=$(AWS_ACCESS_KEY_ID) AWS_SECRET_ACCESS_KEY=$(AWS_SECRET_ACCESS_KEY) \
		AWS_SESSION_TOKEN=$(AWS_SESSION_TOKEN) bin/aws-mock-metadata --availability-zone=$(AVAILABILITY_ZONE) \
		--instance-id=$(INSTANCE_ID) --hostname=$(HOSTNAME) --role-name=$(ROLE_NAME) --role-arn=$(ROLE_ARN) \
		--app-port=$(APP_PORT)

run-macos:
	bin/server-macos

run-linux:
	bin/server-linux

run-docker:
	@docker run -it --rm -p 80:$(APP_PORT) -e AWS_ACCESS_KEY_ID=$(AWS_ACCESS_KEY_ID) \
		-e AWS_SECRET_ACCESS_KEY=$(AWS_SECRET_ACCESS_KEY) -e AWS_SESSION_TOKEN=$(AWS_SESSION_TOKEN) \
		jtblin/aws-mock-metadata:$(GIT_HASH) --availability-zone=$(AVAILABILITY_ZONE) --instance-id=$(INSTANCE_ID) \
		--hostname=$(HOSTNAME) --role-name=$(ROLE_NAME) --role-arn=$(ROLE_ARN) --app-port=$(APP_PORT)

clean:
	rm -f bin/aws-mock-metadata*
	docker rm $(shell docker ps -a -f 'status=exited' -q) || true
	docker rmi $(shell docker images -f 'dangling=true' -q) || true

release: docker
	docker push jtblin/aws-mock-metadata:$(GIT_HASH)
	docker tag -f jtblin/aws-mock-metadata:$(GIT_HASH) jtblin/aws-mock-metadata:latest
	docker push jtblin/aws-mock-metadata:latest