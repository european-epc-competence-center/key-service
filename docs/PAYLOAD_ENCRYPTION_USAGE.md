# Payload Encryption Usage Guide

This document provides a quick reference for using the payload encryption feature in the key-service.

## Overview

The key-service now supports AES-256-GCM encryption for encrypting payloads in service-to-service communication. This feature uses a shared secret to encrypt and decrypt data, providing:

- **Confidentiality**: Data is encrypted and cannot be read without the secret
- **Authenticity**: GCM authentication tag ensures data integrity
- **Simplicity**: Easy to implement in any language/platform

## Configuration

### Enable Payload Encryption

Set the following environment variables:

```bash
# Enable the feature
PAYLOAD_ENCRYPTION_ENABLED=true

# Set the shared secret (must be exactly 32 characters)
PAYLOAD_ENCRYPTION_SECRET="your-32-character-secret-key!"
```

Or use a file path:

```bash
PAYLOAD_ENCRYPTION_ENABLED=true
PAYLOAD_ENCRYPTION_SECRET_PATH="/run/secrets/payload-encryption-secret"
```

### Generate a Secret

Generate a secure 32-character secret:

```bash
# Method 1: OpenSSL
openssl rand -base64 32 | cut -c1-32

# Method 2: Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('base64').slice(0, 32))"

# Method 3: Manual (use any 32 characters)
echo "12345678901234567890123456789012"
```

## API Endpoints

### Check Encryption Status

```bash
GET /encryption/status
```

**Response:**
```json
{
  "enabled": true,
  "algorithm": "AES-256-GCM",
  "format": "base64(iv:authTag:ciphertext)"
}
```

### Encrypt Data

```bash
POST /encrypt
Content-Type: application/json

{
  "data": {
    "message": "Hello, World!",
    "timestamp": 1234567890
  }
}
```

**Response:**
```json
{
  "encryptedData": "YWFiYmNjZGRlZWZmMDAxMTIyMzM6MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY6YWJjZGVm..."
}
```

### Decrypt Data

```bash
POST /decrypt
Content-Type: application/json

{
  "encryptedData": "YWFiYmNjZGRlZWZmMDAxMTIyMzM6MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY6YWJjZGVm..."
}
```

**Response:**
```json
{
  "message": "Hello, World!",
  "timestamp": 1234567890
}
```

## Usage Examples

### Node.js / TypeScript

```typescript
// Encrypt data before sending to another service
const response = await fetch('http://key-service:3000/encrypt', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    data: { userId: 123, action: 'login' }
  })
});

const { encryptedData } = await response.json();

// Send encrypted data to another service
await fetch('http://other-service/api/secure', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ encryptedData })
});

// Decrypt received data
const decryptResponse = await fetch('http://key-service:3000/decrypt', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ encryptedData })
});

const originalData = await decryptResponse.json();
```

### cURL

```bash
# Encrypt
curl -X POST http://localhost:3000/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data": {"message": "Hello"}}'

# Decrypt
curl -X POST http://localhost:3000/decrypt \
  -H "Content-Type: application/json" \
  -d '{"encryptedData": "..."}'
```

### Python

```python
import requests
import json

# Encrypt
encrypt_response = requests.post(
    'http://key-service:3000/encrypt',
    json={'data': {'message': 'Hello', 'value': 123}}
)
encrypted_data = encrypt_response.json()['encryptedData']

# Decrypt
decrypt_response = requests.post(
    'http://key-service:3000/decrypt',
    json={'encryptedData': encrypted_data}
)
original_data = decrypt_response.json()
```

## Spring Boot Integration

For detailed Spring Boot integration with direct AES-256-GCM encryption/decryption in Java (without calling the key-service endpoints), see:

**[docs/payload-encryption-spring-boot.md](./payload-encryption-spring-boot.md)**

This guide includes:
- Complete Java implementation of AES-256-GCM encryption
- Spring Boot service configuration
- Full code examples
- Unit tests
- Security best practices

## Encrypted Data Format

The encrypted data is base64-encoded and contains three parts:

```
base64(iv:authTag:ciphertext)
```

- **IV** (12 bytes): Random initialization vector for GCM mode
- **Auth Tag** (16 bytes): GCM authentication tag for integrity verification
- **Ciphertext** (variable): The actual encrypted data

When decoded and split by `:`, you get three hex-encoded strings.

## Security Notes

### Transport Security
- Always use HTTPS/TLS for communication between services
- Payload encryption provides an additional layer of security but doesn't replace transport security

### Secret Management
- Never commit secrets to version control
- Use environment variables or secrets management systems
- The same secret must be configured on all communicating services
- Rotate secrets regularly

### Secret Requirements
- **Must be exactly 32 bytes (32 ASCII characters)** for AES-256
- Use high-entropy random strings
- Store securely (Docker secrets, Kubernetes secrets, AWS Secrets Manager, etc.)

## Docker Configuration

### Docker Compose

```yaml
services:
  key-service:
    image: key-service:latest
    environment:
      - PAYLOAD_ENCRYPTION_ENABLED=true
      - PAYLOAD_ENCRYPTION_SECRET=${PAYLOAD_ENCRYPTION_SECRET}
    # Or use Docker secrets:
    secrets:
      - payload_encryption_secret
    environment:
      - PAYLOAD_ENCRYPTION_ENABLED=true
      - PAYLOAD_ENCRYPTION_SECRET_PATH=/run/secrets/payload_encryption_secret

secrets:
  payload_encryption_secret:
    file: ./secrets/payload_encryption_secret.txt
```

### Kubernetes

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: key-service-secrets
type: Opaque
stringData:
  payload-encryption-secret: "your-32-character-secret-key!"
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
        image: key-service:latest
        env:
        - name: PAYLOAD_ENCRYPTION_ENABLED
          value: "true"
        - name: PAYLOAD_ENCRYPTION_SECRET
          valueFrom:
            secretKeyRef:
              name: key-service-secrets
              key: payload-encryption-secret
```

## Troubleshooting

### "Encryption is not enabled or configured"
- Ensure `PAYLOAD_ENCRYPTION_ENABLED=true`
- Verify `PAYLOAD_ENCRYPTION_SECRET` is set and exactly 32 characters

### "Invalid encrypted data format"
- Check that the encrypted data is valid base64
- Ensure the data hasn't been corrupted during transmission
- Verify you're using the same encryption format

### "Invalid IV size" or "Invalid auth tag size"
- The encrypted data may be corrupted
- Ensure both services use compatible encryption implementations

### Authentication failed during decryption
- Both services must use the exact same 32-character secret
- The data may have been tampered with
- Verify the secret configuration on both sides

## Performance Considerations

- Encryption/decryption operations are fast (typically < 1ms for small payloads)
- Consider caching frequently accessed encrypted data if appropriate
- For very large payloads (> 100KB), consider streaming encryption or compression

## Testing

Use the test endpoints to verify encryption is working:

```bash
# Test round-trip encryption/decryption
ENCRYPTED=$(curl -s -X POST http://localhost:3000/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data":{"test":"value"}}' | jq -r '.encryptedData')

curl -X POST http://localhost:3000/decrypt \
  -H "Content-Type: application/json" \
  -d "{\"encryptedData\":\"$ENCRYPTED\"}"
```

Expected output: `{"test":"value"}`

## Related Documentation

- [Spring Boot Integration Guide](./payload-encryption-spring-boot.md) - Complete Java implementation
- [Security and Key Management Concept](./security_and_key_management_concept.md) - Overall security architecture
- [README.md](../README.md) - Main project documentation

