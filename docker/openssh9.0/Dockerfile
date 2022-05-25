FROM alpine:3.16

# Installing the openssh package
RUN apk --update add --no-cache openssh

# install host key
COPY ssh_host_ed25519_key /etc/ssh/
RUN chmod 0600 /etc/ssh/ssh_host_ed25519_key
# install custom config
COPY sshd_config /etc/ssh/

# Remove startup script
RUN rm /etc/init.d/sshd

# Add test user, unlocked with no password
RUN adduser test -D -g ''
RUN passwd -d test

# copy user's public key
COPY ecdsa_id.pub /home/test/.ssh/authorized_keys

EXPOSE 22
CMD ["/usr/sbin/sshd", "-d"]
