# Request Encryption Quick Start

Quick reference for configuring request encryption.

## Configuration

### Environment Variables

```bash
# Enable automatic request decryption
REQUEST_ENCRYPTION_ENABLED=true

# Set the shared secret (exactly 32 characters)
REQUEST_ENCRYPTION_SHARED_SECRET="your-32-character-secret-key!"
```

### Generate a Secret

```bash
# Generate a random 32-character secret
openssl rand -base64 32 | cut -c1-32
```

## How It Works

1. **Client** encrypts request payload with the shared secret
2. **Client** sends `{ "encryptedData": "..." }` to any endpoint
3. **Controller** passes the raw request to the service layer
4. **Service layer** automatically detects and decrypts the payload
5. **Service** processes the decrypted data and returns plain JSON response

**Security Note**: Decryption happens in the service layer (not in an interceptor), keeping decrypted secrets isolated from the request pipeline where they could be accidentally logged.

## Supported Endpoints

All POST endpoints automatically support encrypted requests:
- `POST /generate`
- `POST /sign/vc/:type`
- `POST /sign/vp/:type`

## Docker Example

```yaml
services:
  key-service:
    image: key-service:latest
    environment:
      - REQUEST_ENCRYPTION_ENABLED=true
      - REQUEST_ENCRYPTION_SHARED_SECRET=${REQUEST_ENCRYPTION_SHARED_SECRET}
```

## Kubernetes Example

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: request-encryption-secret
stringData:
  shared-secret: "your-32-character-secret-key!"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: key-service
spec:
  template:
    spec:
      containers:
      - name: key-service
        env:
        - name: REQUEST_ENCRYPTION_ENABLED
          value: "true"
        - name: REQUEST_ENCRYPTION_SHARED_SECRET
          valueFrom:
            secretKeyRef:
              name: request-encryption-secret
              key: shared-secret
```

## Client Implementation

See detailed implementation guides:
- **Java/Spring Boot**: [payload-encryption-spring-boot.md](./payload-encryption-spring-boot.md)
- **Multi-language examples**: [REQUEST_ENCRYPTION_USAGE.md](./REQUEST_ENCRYPTION_USAGE.md)

## Security

- ✅ **32-character secret** required (256 bits for AES-256)
- ✅ **Same secret** on all communicating services
- ✅ **Environment variable only** (no file paths)
- ✅ **Always use HTTPS/TLS** for transport security
- ✅ **Rotate secrets** regularly


