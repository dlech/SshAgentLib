This directory contains a `Dockerfile` to create a server that only accepts
SSH connections authenticated with a certificate.

**Fix file permissions:**

Git only preserves the executable bit, so in order to use the private key with
`ssh-keygen`, we need to fix the file permissions first:

```bash
chmod 600 test-CA
```

**To create a certificate using the test-CA use the following command:**

```bash
ssh-keygen -t rsa-sha2-256 -s test-CA -I test -n testtest -V +3600d -z 1 my-key-cert.pub
```

The passphrase for `test-CA` is `testest`.

This generates a certificate:
- with identity "test"
- with principal "testtest"
- valid for 10 years

**To run the sshd docker image:**

build the image with

```bash
docker build -t openssh-cert-test <path-to-this-directory>
```

then run it with

```bash
docker run --rm -p 22222:22 openssh-cert-test
```

You will get sshd debug output in the console. Use <kbd>CTRL</kbd>+<kbd>\</kbd> to stop.
