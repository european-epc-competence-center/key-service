# Payload Encryption - Spring Boot Integration Guide

This guide shows how to implement compatible AES-256-GCM payload encryption in Spring Boot applications to communicate securely with the key-service.

## Overview

The key-service uses **AES-256-GCM** (Galois/Counter Mode) encryption for payload encryption with a shared 256-bit secret. This provides:

- **Confidentiality**: Data is encrypted and cannot be read by third parties
- **Authenticity**: The authentication tag ensures data hasn't been tampered with
- **Simplicity**: Direct use of a 256-bit shared secret (no key derivation)

**Format**: `base64(iv:authTag:ciphertext)`
- IV: 12 bytes (96 bits) - random initialization vector
- Auth Tag: 16 bytes (128 bits) - GCM authentication tag
- Ciphertext: encrypted data (variable length)

## Requirements

- Java 8 or higher
- Spring Boot 2.x or 3.x
- A 32-character shared secret (same as configured in key-service)

## Spring Boot Implementation

### 1. Add Dependencies (if needed)

Standard Java cryptography is included in the JDK. No additional dependencies required.

### 2. Create PayloadEncryptionService

```java
package com.example.service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Payload encryption service compatible with key-service AES-256-GCM encryption.
 * 
 * Format: base64(iv:authTag:ciphertext)
 * - IV: 12 bytes (96 bits)
 * - Auth Tag: 16 bytes (128 bits)
 * - Ciphertext: variable length
 */
@Service
public class PayloadEncryptionService {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12; // 96 bits
    private static final int GCM_TAG_LENGTH = 16; // 128 bits
    
    private final SecretKeySpec secretKey;
    private final SecureRandom secureRandom;
    
    public PayloadEncryptionService(
            @Value("${payload.encryption.secret}") String secret) {
        
        // Validate secret length (must be exactly 32 bytes for AES-256)
        byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        if (secretBytes.length != 32) {
            throw new IllegalArgumentException(
                "Secret must be exactly 32 bytes (256 bits). Got: " + secretBytes.length);
        }
        
        this.secretKey = new SecretKeySpec(secretBytes, "AES");
        this.secureRandom = new SecureRandom();
    }
    
    /**
     * Encrypt data using AES-256-GCM.
     * 
     * @param plaintext The data to encrypt
     * @return Base64-encoded encrypted data in format: base64(iv:authTag:ciphertext)
     * @throws Exception if encryption fails
     */
    public String encrypt(String plaintext) throws Exception {
        // Generate random IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        
        // Initialize cipher
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
        
        // Encrypt
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] ciphertextWithTag = cipher.doFinal(plaintextBytes);
        
        // Split ciphertext and auth tag
        int ciphertextLength = ciphertextWithTag.length - GCM_TAG_LENGTH;
        byte[] ciphertext = new byte[ciphertextLength];
        byte[] authTag = new byte[GCM_TAG_LENGTH];
        
        System.arraycopy(ciphertextWithTag, 0, ciphertext, 0, ciphertextLength);
        System.arraycopy(ciphertextWithTag, ciphertextLength, authTag, 0, GCM_TAG_LENGTH);
        
        // Format: iv:authTag:ciphertext (all hex-encoded)
        String combined = bytesToHex(iv) + ":" + 
                          bytesToHex(authTag) + ":" + 
                          bytesToHex(ciphertext);
        
        // Return as base64
        return Base64.getEncoder().encodeToString(combined.getBytes(StandardCharsets.UTF_8));
    }
    
    /**
     * Decrypt data encrypted with AES-256-GCM.
     * 
     * @param encryptedData Base64-encoded encrypted data from encrypt()
     * @return Decrypted plaintext
     * @throws Exception if decryption fails or authentication fails
     */
    public String decrypt(String encryptedData) throws Exception {
        // Decode base64
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
        String combined = new String(decodedBytes, StandardCharsets.UTF_8);
        
        // Split into parts: iv:authTag:ciphertext
        String[] parts = combined.split(":");
        if (parts.length != 3) {
            throw new IllegalArgumentException(
                "Invalid encrypted data format. Expected 3 parts (iv:authTag:ciphertext)");
        }
        
        byte[] iv = hexToBytes(parts[0]);
        byte[] authTag = hexToBytes(parts[1]);
        byte[] ciphertext = hexToBytes(parts[2]);
        
        // Validate sizes
        if (iv.length != GCM_IV_LENGTH) {
            throw new IllegalArgumentException(
                "Invalid IV size: expected " + GCM_IV_LENGTH + " bytes, got " + iv.length);
        }
        if (authTag.length != GCM_TAG_LENGTH) {
            throw new IllegalArgumentException(
                "Invalid auth tag size: expected " + GCM_TAG_LENGTH + " bytes, got " + authTag.length);
        }
        
        // Combine ciphertext and auth tag for Java's Cipher API
        byte[] ciphertextWithTag = new byte[ciphertext.length + authTag.length];
        System.arraycopy(ciphertext, 0, ciphertextWithTag, 0, ciphertext.length);
        System.arraycopy(authTag, 0, ciphertextWithTag, ciphertext.length, authTag.length);
        
        // Initialize cipher
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
        
        // Decrypt (this also verifies the auth tag)
        byte[] plaintextBytes = cipher.doFinal(ciphertextWithTag);
        
        return new String(plaintextBytes, StandardCharsets.UTF_8);
    }
    
    /**
     * Convert bytes to hex string.
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    /**
     * Convert hex string to bytes.
     */
    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
}
```

### 3. Configuration

Add to your `application.properties` or `application.yml`:

```properties
# Must be exactly 32 characters for AES-256
payload.encryption.secret=your-32-character-secret-key!
```

Or use environment variables:

```properties
payload.encryption.secret=${PAYLOAD_ENCRYPTION_SECRET}
```

### 4. Usage Example

```java
package com.example.controller;

import com.example.service.PayloadEncryptionService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class KeyServiceClient {

    @Autowired
    private PayloadEncryptionService encryptionService;
    
    @Autowired
    private ObjectMapper objectMapper;
    
    /**
     * Encrypt a request payload before sending to key-service.
     */
    public String encryptRequest(Object requestPayload) throws Exception {
        // Convert payload to JSON
        String json = objectMapper.writeValueAsString(requestPayload);
        
        // Encrypt
        return encryptionService.encrypt(json);
    }
    
    /**
     * Decrypt a response payload from key-service.
     */
    public <T> T decryptResponse(String encryptedData, Class<T> responseClass) throws Exception {
        // Decrypt
        String json = encryptionService.decrypt(encryptedData);
        
        // Parse JSON
        return objectMapper.readValue(json, responseClass);
    }
}
```

### 5. Calling Key Service Endpoints

```java
@Service
public class KeyServiceApiClient {

    @Autowired
    private RestTemplate restTemplate;
    
    @Autowired
    private PayloadEncryptionService encryptionService;
    
    @Autowired
    private ObjectMapper objectMapper;
    
    @Value("${key-service.url}")
    private String keyServiceUrl;
    
    /**
     * Test encryption with key-service.
     */
    public void testEncryption() throws Exception {
        // Create test data
        Map<String, Object> testData = Map.of(
            "message", "Hello from Spring Boot",
            "timestamp", System.currentTimeMillis()
        );
        
        // Convert to JSON and encrypt
        String json = objectMapper.writeValueAsString(testData);
        String encrypted = encryptionService.encrypt(json);
        
        // Send to key-service decrypt endpoint
        Map<String, String> request = Map.of("encryptedData", encrypted);
        
        ResponseEntity<Map> response = restTemplate.postForEntity(
            keyServiceUrl + "/decrypt",
            request,
            Map.class
        );
        
        System.out.println("Decrypted by key-service: " + response.getBody());
    }
}
```

## Testing

### Unit Test

```java
package com.example.service;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class PayloadEncryptionServiceTest {

    private static final String TEST_SECRET = "12345678901234567890123456789012"; // 32 chars
    
    @Test
    void testEncryptDecrypt() throws Exception {
        PayloadEncryptionService service = new PayloadEncryptionService(TEST_SECRET);
        
        String plaintext = "Hello, World!";
        String encrypted = service.encrypt(plaintext);
        String decrypted = service.decrypt(encrypted);
        
        assertEquals(plaintext, decrypted);
    }
    
    @Test
    void testJsonEncryptDecrypt() throws Exception {
        PayloadEncryptionService service = new PayloadEncryptionService(TEST_SECRET);
        
        String json = "{\"message\":\"test\",\"value\":123}";
        String encrypted = service.encrypt(json);
        String decrypted = service.decrypt(json);
        
        assertEquals(json, decrypted);
    }
    
    @Test
    void testInvalidSecret() {
        assertThrows(IllegalArgumentException.class, () -> {
            new PayloadEncryptionService("too-short"); // Not 32 characters
        });
    }
}
```

## Environment Variables

For production, use environment variables or secrets management:

```bash
# Docker
docker run -e PAYLOAD_ENCRYPTION_SECRET="your-32-character-secret-key!" your-app

# Kubernetes Secret
kubectl create secret generic app-secrets \
  --from-literal=payload-encryption-secret="your-32-character-secret-key!"
```

## Security Best Practices

1. **Secret Management**
   - Use exactly 32 characters (256 bits) for the secret
   - Never commit secrets to version control
   - Use environment variables or secrets management (Kubernetes secrets, AWS Secrets Manager, etc.)
   - Rotate secrets regularly

2. **Transport Security**
   - Always use HTTPS/TLS for transport
   - Payload encryption provides confidentiality but TLS is still essential for defense in depth

3. **Secret Generation**
   ```bash
   # Generate a random 32-character secret
   openssl rand -base64 32 | cut -c1-32
   ```

4. **Same Secret on All Services**
   - The same 32-character secret must be configured on both key-service and your Spring Boot application
   - Consider using a centralized secrets management system

## Troubleshooting

### Invalid encrypted data format
- Ensure the encrypted data is properly base64-encoded
- Check that the format is: `base64(iv:authTag:ciphertext)`

### Authentication failed
- Verify both services use the exact same 32-character secret
- Check that the encrypted data wasn't corrupted during transmission

### Invalid secret length
- The secret must be exactly 32 bytes (32 ASCII characters)
- Use UTF-8 encoding for the secret string

## Example: Complete Integration

```java
@RestController
@RequestMapping("/api")
public class SecureApiController {

    @Autowired
    private PayloadEncryptionService encryptionService;
    
    @Autowired
    private ObjectMapper objectMapper;
    
    /**
     * Receive encrypted payload, decrypt, process, and return encrypted response.
     */
    @PostMapping("/secure-endpoint")
    public Map<String, String> handleSecureRequest(@RequestBody Map<String, String> request) throws Exception {
        // Decrypt incoming payload
        String encryptedData = request.get("encryptedData");
        String decryptedJson = encryptionService.decrypt(encryptedData);
        Map<String, Object> payload = objectMapper.readValue(decryptedJson, Map.class);
        
        // Process payload
        Map<String, Object> response = processPayload(payload);
        
        // Encrypt response
        String responseJson = objectMapper.writeValueAsString(response);
        String encryptedResponse = encryptionService.encrypt(responseJson);
        
        return Map.of("encryptedData", encryptedResponse);
    }
    
    private Map<String, Object> processPayload(Map<String, Object> payload) {
        // Your business logic here
        return Map.of("status", "success", "processed", payload);
    }
}
```

## Additional Resources

- [Java Cryptography Architecture (JCA) Reference Guide](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html)
- [AES-GCM Specification](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [Spring Boot Security Best Practices](https://spring.io/guides/topicals/spring-security-architecture)

