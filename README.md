# aws-mock-metadata

The [ec2 instance metadata service](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
runs on each ec2 instance and provide an api to retrieve information about the running instance as well as 
getting credentials based on the IAM role. 

I needed to run this service locally (in docker) in order to be able to troubleshoot issues with [kubernetes](https://github.com/kubernetes/kubernetes/)
with the aws provider. I found an existing python based [service](https://github.com/dump247/aws-mock-metadata) but
for some reasons I couldn't get it to work in docker with my temporary credentials. I also needed additional features 
like being able to return an instance id, availability zone, etc. so after a few hours of fighting I decided to 
create this one.

## Docker quick start

	docker run -it --rm -p 80:$(APP_PORT) -e APP_PORT=$(APP_PORT) -e AWS_ACCESS_KEY_ID=$(AWS_ACCESS_KEY_ID) \
    		-e AWS_SECRET_ACCESS_KEY=$(AWS_SECRET_ACCESS_KEY) jtblin/aws-mock-metadata

In your other docker image, install iptables and have a startup script that point 169.254.169.254 to the docker host
before starting your program:

	iptables -t nat -A OUTPUT -d 169.254.169.254 -j DNAT --to-destination ${HOST}

## Development

### Configuration

Set the following environment variables or create a .env file with the following information:

* `APP_PORT`: port to run the container on (default 8080)
* `AWS_ACCESS_KEY_ID`: aws access key
* `AWS_SECRET_ACCESS_KEY`: aws secret access key
* `AWS_SESSION_TOKEN`: aws session token (optional)

### Dependencies

You need to have go installed locally.

Install Godep

    go get github.com/tools/godep

### Run

Run it. This will run the bare server on localhost.

    make build run

Run it on 169.254.169.254 on Mac OSX or linux.

    make build run-macos
    make build run-linux

Run in docker

	make docker run-docker

## TODO

* Pass values for endpoints via command line arguments