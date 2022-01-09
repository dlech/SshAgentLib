FROM alpine:latest
# Installing the openssh and bash package, removing the apk cache
RUN apk --update add --no-cache openssh
RUN rm -rf /var/cache/apk/*
RUN /usr/bin/ssh-keygen -A

# Remove startup script
RUN rm /etc/init.d/sshd

# Only allow login via certificates
RUN echo -e 'PermitRootLogin no\nPasswordAuthentication no\nAuthorizedKeysFile none\nX11Forwarding no\nAllowTcpForwarding no\n' >> /etc/ssh/sshd_config
# Allow login via certificates with principals
RUN echo -e 'TrustedUserCAKeys /etc/ssh/test-CA.pub\nAuthorizedPrincipalsFile /etc/ssh/principals/%u\n' >> /etc/ssh/sshd_config

# Add CA certificate
RUN echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDLYyiqcB+kf4MK3BOgoiYn4uvYfh2ALvE2kc6Qc9upKVL7Z2ASv+y5ZQc3Mb+vfEFz6CE/a8vrEhb9w8iQtnqwJLcDgKBc2EycTIRJP/liasDnTkMOrXxqPY3AVwTXRL3ubN3/oH7TZam/M4S3iLtgcaA8st7j17qKOphmuEDk4Wnbgq2KuOddjMbw4VnePJ0J3kDwbVRl9t/pjcq4BQuPV6ZogQEURYPSIaBknNcs53J1RfuMpZslp8wNREXkFr4to0CN4A3BDZjHCRR4K1XlSP9wl/Net37lVuWG1eQMQiNGgKHhOVlA96kWqke/ozoBtkL0in436tqdiwDEEs/7 msabatier@vm-eco-bionic' > /etc/ssh/test-CA.pub

# Add test user, unlocked with no password
RUN adduser test -D -g ''
RUN passwd -d test
# Allow use of certificates with principal "testtest" to login as user "test"
RUN mkdir /etc/ssh/principals
RUN echo 'testtest' > /etc/ssh/principals/test

EXPOSE 22
CMD ["/usr/sbin/sshd", "-d"]
