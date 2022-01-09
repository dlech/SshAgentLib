Test key for use in conjunction with the `cert_test` Docker image.

**Fix file permissions:**

For the integration test to work correctly, the file permission of the private
key must be fixed.

```bash
chmod 600 test_key
```
