# Request Encryption Usage Guide

This document explains how to send encrypted requests to the key-service. **Only requests need to be encrypted - responses are returned as plain JSON.**

## Overview

The key-service can decrypt incoming request payloads using AES-256-GCM encryption with a shared secret. This allows clients to:

- Send sensitive data (secrets, credentials, etc.) encrypted
- Receive plain JSON responses (simpler client implementation)
- Use HTTPS for transport security as an additional layer

**Use Case:** When you want to add an extra layer of security for sensitive request data beyond HTTPS.

## Configuration

### On the Key Service (NestJS)

```bash
# Enable request encryption
export REQUEST_ENCRYPTION_ENABLED=true

# Set the request encryption shared secret (exactly 32 characters)
export REQUEST_ENCRYPTION_SHARED_SECRET="your-32-character-secret-key!"
```

### On the Client (Spring Boot, Node.js, etc.)

Use the **same 32-character secret** to encrypt requests before sending.

## How It Works

The service automatically detects and decrypts encrypted requests at the **service layer**:

1. **Client encrypts request** → Converts payload to JSON and encrypts with shared secret
2. **Client sends** → POSTs to any endpoint with `{ encryptedData: "..." }`
3. **Controller passes through** → Controller receives the raw request body
4. **Service layer decrypts** → AppService detects and decrypts the `encryptedData` field
5. **Service processes** → Business logic works with plain data (transparent decryption)
6. **Service responds** → Returns plain JSON response

**Key Point**: Decryption happens in the service layer (after the controller), keeping decrypted secrets isolated and reducing the risk of accidental logging in the request pipeline.

## API Usage

### Standard Encrypted Request Format

Send encrypted payloads to **any existing endpoint** using this format:

```json
{
  "encryptedData": "base64-encoded-encrypted-payload"
}
```

The service layer automatically:
- Detects the `encryptedData` field in the AppService
- Decrypts the payload using the shared secret
- Extracts the decrypted data for processing
- Handles both encrypted and plain requests seamlessly

**Security benefit**: Decrypted data stays in the service layer and is never exposed in the request pipeline where it could be accidentally logged.

### Example: Encrypted Key Generation Request

**Client Side (Spring Boot):**

```java
// Create the actual request
GenerateKeyRequest request = new GenerateKeyRequest();
request.setSecrets(List.of("user-secret"));
request.setIdentifier("my-key");
request.setSignatureType("Ed25519");
request.setKeyType("JWK");

// Convert to JSON and encrypt
String json = objectMapper.writeValueAsString(request);
String encrypted = payloadEncryptionService.encrypt(json);

// Send encrypted request
Map<String, String> encryptedPayload = Map.of("encryptedData", encrypted);
ResponseEntity<Map> response = restTemplate.postForEntity(
    "http://key-service:3000/generate",
    encryptedPayload,
    Map.class
);

// Response is plain JSON - no decryption needed
Map<String, Object> plainResponse = response.getBody();
```

**Key Service Response (Plain JSON):**

```json
{
  "message": "Key pair generated successfully",
  "identifier": "my-key",
  "publicKey": {...}
}
```

## Testing Decryption

To test if your encryption is working correctly, send an encrypted request to any endpoint.

For example, encrypt a key generation request and send it:

```bash
# Example encrypted request (you'd generate this with your encryption service)
curl -X POST http://localhost:3000/generate \
  -H "Content-Type: application/json" \
  -d '{
    "encryptedData": "your-encrypted-base64-string-here"
  }'
```

If the encryption is correct, the service will decrypt it automatically and process the request normally.

## Client Implementation Examples

### Spring Boot (Java)

**1. Create the Encryption Service**

```java
@Service
public class PayloadEncryptionService {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private final SecretKeySpec secretKey;
    
    public PayloadEncryptionService(@Value("${payload.encryption.secret}") String secret) {
        byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        if (secretBytes.length != 32) {
            throw new IllegalArgumentException("Secret must be exactly 32 bytes");
        }
        this.secretKey = new SecretKeySpec(secretBytes, "AES");
    }
    
    public String encrypt(String plaintext) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
        
        byte[] ciphertextWithTag = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        
        // Split ciphertext and auth tag
        int ciphertextLength = ciphertextWithTag.length - 16;
        byte[] ciphertext = new byte[ciphertextLength];
        byte[] authTag = new byte[16];
        System.arraycopy(ciphertextWithTag, 0, ciphertext, 0, ciphertextLength);
        System.arraycopy(ciphertextWithTag, ciphertextLength, authTag, 0, 16);
        
        // Format: iv:authTag:ciphertext (hex-encoded, then base64)
        String combined = bytesToHex(iv) + ":" + bytesToHex(authTag) + ":" + bytesToHex(ciphertext);
        return Base64.getEncoder().encodeToString(combined.getBytes(StandardCharsets.UTF_8));
    }
    
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
```

**2. Use in Your Service**

```java
@Service
public class KeyServiceClient {
    
    @Autowired
    private RestTemplate restTemplate;
    
    @Autowired
    private PayloadEncryptionService encryptionService;
    
    @Autowired
    private ObjectMapper objectMapper;
    
    @Value("${key-service.url}")
    private String keyServiceUrl;
    
    public Map<String, Object> generateKeyEncrypted(GenerateKeyRequest request) throws Exception {
        // Encrypt the request
        String json = objectMapper.writeValueAsString(request);
        String encrypted = encryptionService.encrypt(json);
        
        // Send encrypted request
        Map<String, String> payload = Map.of("encryptedData", encrypted);
        ResponseEntity<Map> response = restTemplate.postForEntity(
            keyServiceUrl + "/generate",
            payload,
            Map.class
        );
        
        // Response is plain JSON - use directly
        return response.getBody();
    }
    
    public Map<String, Object> signCredentialEncrypted(SignRequest request, String signType) throws Exception {
        // Encrypt the request
        String json = objectMapper.writeValueAsString(request);
        String encrypted = encryptionService.encrypt(json);
        
        // Send encrypted request
        Map<String, String> payload = Map.of("encryptedData", encrypted);
        ResponseEntity<Map> response = restTemplate.postForEntity(
            keyServiceUrl + "/sign/vc/" + signType,
            payload,
            Map.class
        );
        
        // Response is plain JSON - use directly
        return response.getBody();
    }
}
```

### Node.js / TypeScript

```typescript
import crypto from 'crypto';

class PayloadEncryptionService {
  private secret: Buffer;

  constructor(secret: string) {
    this.secret = Buffer.from(secret, 'utf8');
    if (this.secret.length !== 32) {
      throw new Error('Secret must be exactly 32 bytes');
    }
  }

  encrypt(data: string): string {
    // Generate random IV
    const iv = crypto.randomBytes(12);
    
    // Create cipher
    const cipher = crypto.createCipheriv('aes-256-gcm', this.secret, iv);
    
    // Encrypt
    let ciphertext = cipher.update(data, 'utf8', 'hex');
    ciphertext += cipher.final('hex');
    
    // Get auth tag
    const authTag = cipher.getAuthTag();
    
    // Format: iv:authTag:ciphertext
    const combined = [
      iv.toString('hex'),
      authTag.toString('hex'),
      ciphertext,
    ].join(':');
    
    // Return as base64
    return Buffer.from(combined, 'utf8').toString('base64');
  }
}

// Usage
const encryptionService = new PayloadEncryptionService('your-32-character-secret-key!');

const request = {
  secrets: ['user-secret'],
  identifier: 'my-key',
  signatureType: 'Ed25519',
  keyType: 'JWK'
};

const encrypted = encryptionService.encrypt(JSON.stringify(request));

const response = await fetch('http://key-service:3000/generate', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ encryptedData: encrypted })
});

// Response is plain JSON
const plainResponse = await response.json();
console.log(plainResponse);
```

### Python

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os

class PayloadEncryptionService:
    def __init__(self, secret: str):
        self.secret = secret.encode('utf-8')
        if len(self.secret) != 32:
            raise ValueError("Secret must be exactly 32 bytes")
        self.aesgcm = AESGCM(self.secret)
    
    def encrypt(self, data: str) -> str:
        # Generate random IV
        iv = os.urandom(12)
        
        # Encrypt (AESGCM automatically adds auth tag)
        ciphertext_with_tag = self.aesgcm.encrypt(iv, data.encode('utf-8'), None)
        
        # Split ciphertext and auth tag
        ciphertext = ciphertext_with_tag[:-16]
        auth_tag = ciphertext_with_tag[-16:]
        
        # Format: iv:authTag:ciphertext (hex-encoded)
        combined = f"{iv.hex()}:{auth_tag.hex()}:{ciphertext.hex()}"
        
        # Return as base64
        return base64.b64encode(combined.encode('utf-8')).decode('utf-8')

# Usage
import requests
import json

encryption_service = PayloadEncryptionService('your-32-character-secret-key!')

request = {
    'secrets': ['user-secret'],
    'identifier': 'my-key',
    'signatureType': 'Ed25519',
    'keyType': 'JWK'
}

encrypted = encryption_service.encrypt(json.dumps(request))

response = requests.post(
    'http://key-service:3000/generate',
    json={'encryptedData': encrypted}
)

# Response is plain JSON
plain_response = response.json()
print(plain_response)
```

## Configuration Examples

### Docker Compose

```yaml
services:
  key-service:
    image: key-service:latest
    environment:
      - REQUEST_ENCRYPTION_ENABLED=true
      - REQUEST_ENCRYPTION_SHARED_SECRET=${REQUEST_ENCRYPTION_SHARED_SECRET}
  
  your-app:
    image: your-app:latest
    environment:
      - KEY_SERVICE_URL=http://key-service:3000
      - REQUEST_ENCRYPTION_SHARED_SECRET=${REQUEST_ENCRYPTION_SHARED_SECRET}
```

### Kubernetes

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: request-encryption-secret
type: Opaque
stringData:
  shared-secret: "your-32-character-secret-key!"
---
# Key Service Deployment
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
---
# Your App Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: your-app
spec:
  template:
    spec:
      containers:
      - name: your-app
        env:
        - name: REQUEST_ENCRYPTION_SHARED_SECRET
          valueFrom:
            secretKeyRef:
              name: request-encryption-secret
              key: shared-secret
```

## Security Notes

1. **Transport Security**: Always use HTTPS/TLS in addition to payload encryption
2. **Secret Rotation**: Rotate the shared secret periodically
3. **Secret Storage**: Never commit secrets to version control
4. **Same Secret**: All clients and the key-service must use the exact same 32-character secret
5. **Response Security**: Responses are plain JSON, so ensure your network is secure (VPN, service mesh, etc.)

## Why Decrypt-Only?

This pattern is useful when:
- Request data is sensitive (secrets, credentials, PII)
- Response data is less sensitive (public keys, status messages)
- You want to simplify client implementation (no need to decrypt responses)
- You're already using HTTPS for transport security

## Troubleshooting

### "Request encryption is not enabled"
- Set `REQUEST_ENCRYPTION_ENABLED=true` on the key-service
- Verify `REQUEST_ENCRYPTION_SHARED_SECRET` is configured (exactly 32 characters)

### "Invalid encrypted data format"
- Check that your client is formatting as: `base64(iv:authTag:ciphertext)`
- Ensure all parts are hex-encoded before base64 encoding

### Decryption fails
- Verify both client and service use the **exact same** 32-character secret
- Check that data wasn't corrupted during transmission

## Complete Example Flow

```java
// 1. Client creates request
GenerateKeyRequest request = new GenerateKeyRequest();
request.setSecrets(List.of("my-secret"));
request.setIdentifier("key-1");
request.setSignatureType("Ed25519");
request.setKeyType("JWK");

// 2. Client encrypts request
String json = objectMapper.writeValueAsString(request);
String encrypted = encryptionService.encrypt(json);

// 3. Client sends encrypted request
Map<String, String> payload = Map.of("encryptedData", encrypted);
Map<String, Object> response = restTemplate.postForObject(
    "http://key-service:3000/generate",
    payload,
    Map.class
);

// 4. Service decrypts, processes, returns plain JSON
// 5. Client uses plain response directly
System.out.println("Success: " + response.get("message"));
```

That's it! Simple and secure. ✅

