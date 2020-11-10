FROM alpine

ARG ADDR=0.0.0.0
ARG LOGIN=/bin/login
ARG PORT=23
ARG USER=user

ENV CMD "/usr/sbin/telnetd -p $PORT -b $ADDR -l $LOGIN -F"

EXPOSE $PORT

RUN apk update && apk upgrade && apk add busybox-extras
RUN adduser -D $USER && echo -e "password\npassword\n" | passwd $USER

RUN echo "$CMD" | tee cmd.sh && chmod +x cmd.sh
CMD ./cmd.sh