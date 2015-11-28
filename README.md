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

	docker run -it --rm -p 80:8080 -e AWS_ACCESS_KEY_ID=$(AWS_ACCESS_KEY_ID) \
    		-e AWS_SECRET_ACCESS_KEY=$(AWS_SECRET_ACCESS_KEY) jtblin/aws-mock-metadata \
    		--availability-zone=<az> --instance-id=<id> --hostname=<name> --role-name=<role> --role-arn=<arn>
    		--vpc-id=<vpc-id> --private-ip=<ip>

In your other docker image, install iptables and have a startup script that point 169.254.169.254 to the docker host
before starting your program:

	iptables -t nat -A OUTPUT -d 169.254.169.254 -j DNAT --to-destination ${HOST}

## Development

### Configuration

Set the following environment variables or create a .env file with the following information:

* `AWS_ACCESS_KEY_ID`: aws access key
* `AWS_SECRET_ACCESS_KEY`: aws secret access key

Command line arguments:

* `APP_PORT`: port to run the container on (default 8080)
* `AVAILABILITY_ZONE`: ec2 availability zone e.g. ap-southeast-2 (optional)
* `AWS_SESSION_TOKEN`: aws session token (optional)
* `HOSTNAME`: ec2 hostname (optional)
* `INSTANCE_ID`: ec2 instance id (optional)
* `PRIVATE_IP`: ec2 private ip address (optional)
* `ROLE_ARN`: arn for the role to assume to generate temporary credentials (optional)
* `ROLE_NAME`: ec2 role name assigned to the instance (optional)
* `VPC_ID`: vpc id (optional)

**Note**: you will need to have `sts:AssumeRole` for the role that you want to use to generate temporary credentials.
The role also needs to have a trust relationship with the account that you use to assume the role, see
http://stackoverflow.com/questions/21956794/aws-assumerole-authorization-not-working/33850060#33850060.

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
