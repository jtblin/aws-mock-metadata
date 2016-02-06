FROM alpine:3.3
MAINTAINER Jerome Touffe-Blin <jtblin@gmail.com>

RUN apk --update add ca-certificates \
	&& rm -rf /var/cache/apk/*

ADD /bin/aws-mock-metadata-linux /bin/aws-mock-metadata

EXPOSE 45000
ENTRYPOINT ["aws-mock-metadata"]