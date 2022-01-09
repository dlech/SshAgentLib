## To create a certficate using the test-CA use the following command :
```bash
ssh-keygen -t rsa-sha2-256 -s test-CA -I test -n testtest -V +3600d -z 1 test_keeagent.pub
```
This generates a certificate:
- with identity "test"
- valid for 10 years
- with principal "testtest"

## To run the sshd docker image :
build the image with
```bash
sudo docker build -t keeagent-cert-test  -f Dockerfile .
```
then run it with
```bash
sudo docker run -p 2222:22  keeagent-cert-test:latest
```
you will get sshd debug output in the console
