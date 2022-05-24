FROM alpine:latest

# Installing the openssh package
RUN apk --update add --no-cache openssh

# Generate host keys
RUN /usr/bin/ssh-keygen -A
# Remove startup script
RUN rm /etc/init.d/sshd

# Only allow login via certificates
RUN echo -e 'PermitRootLogin no\nPasswordAuthentication no\nAuthorizedKeysFile none\nX11Forwarding no\nAllowTcpForwarding no\n' >> /etc/ssh/sshd_config
# Allow login via certificates with principals
RUN echo -e 'TrustedUserCAKeys /etc/ssh/test-CA.pub\nAuthorizedPrincipalsFile /etc/ssh/principals/%u\n' >> /etc/ssh/sshd_config

# Add CA certificate
COPY test-CA.pub /etc/ssh/

# Add test user, unlocked with no password
RUN adduser test -D -g ''
RUN passwd -d test
# Allow use of certificates with principal "testtest" to login as user "test"
RUN mkdir /etc/ssh/principals
RUN echo 'testtest' > /etc/ssh/principals/test

EXPOSE 22
CMD ["/usr/sbin/sshd", "-d"]
