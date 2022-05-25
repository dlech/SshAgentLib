This directory contains a `Dockerfile` to create a server running OpenSSH 9.0.


**To run the sshd docker image:**

build the image with

```bash
docker build -t test-openssh9.0 <path-to-this-directory>
```

then run it with

```bash
docker run --rm -p 22221:22 test-openssh9.0
```

You will get sshd debug output in the console. Use <kbd>CTRL</kbd>+<kbd>\</kbd> to stop.
