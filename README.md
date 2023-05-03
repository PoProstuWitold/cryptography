# Cryptography

**Disclaimer**: I was inspired by [article](https://fireship.io/lessons/node-crypto-examples/) of ***Jeff Delaney*** known as ***Fireship*** 

Small program to demonstrate most important cryptography concepts. Written using Node.js Crypto module and TypeScript.



# Cryptography Concepts
## 1. Hash
Process that takes an input value of any length and outputs a fixed length value. Hashing algorithms like SHA produce a random, unique, fixed-length string from a given input.
```ts
const hash1 = await cryptoService.createHash('chomik123!')
const hash2 = await cryptoService.createHash('chomik123!')
console.log(hash1 === hash2) // true
```


## 2. Salt 
Random string added to the input before hashing to make the hash more unique and harder to guess
```ts
```

## 3. HMAC
Keyed hash of data that allows you to verify both the authenticity and originator of the data.
```ts
const hmac1 = await cryptoService.createHmac('chomcio123!', 'secret_hamster')
const hmac2 = await cryptoService.createHmac('chomcio123!', 'secret_hamster')
console.log(hmac1 === hmac2) // true

```

## 4. Symmetric Encryption
Ping a message confidential while allowing it to be reversible with the proper key. In symmetric encryption, the same key is used to encrypt and decrypt the message
```ts
const message = 'Homster'

const encryptedMessage = await cryptoService.symmetricEncrypt(message)
const decryptedMessage = await cryptoService.symmetricDecrypt(encryptedMessage)
console.log(message === decryptedMessage) // true
```

## 5. Keypairs
An algorithm like RSA that generates a keypair containing a public and private key. The private key should be kept secret, while the public key can be shared freely.
```ts
const modulusLength = 2048

const { 
	privateKey, 
	publicKey  
} = await cryptoService.generateKeyPair(modulusLength)
```

## 6. Asymmetric Encryption
Encryption that depends on two keys. Encrypt a message with the public key and decrypt it with the private key
```ts
const { 
	privateKey, 
	publicKey  
} = await cryptoService.generateKeyPair(2048)

const encryptedMessage = await cryptoService.publicEncrypt(publicKey, message)
const decryptedMessage = await cryptoService.privateDecrypt(privateKey, encryptedMessage)

// we need to call toString method, 
// because decryptedMessage (and encryptedMessage) is Buffer
console.log(decryptedMessage.toString() === message) // true
```

## 7. Signing
Process of creating a digital signature of a message. A signature is a hash of the original message which is then encrypted with the sender’s private key. The signature can be verified by the recipient using the public key of the sender, which guarantees the original message is authentic and unmodified
```ts
// crypto.service.ts
```