import { randomBytes } from 'node:crypto'
import {
    CryptographyService
} from '../src/crypto/crypto.service'
import { Algorithms, Hashes } from '../src/crypto/constans'

const cryptoService = new CryptographyService({
    algorithm: Algorithms.AES_256_CBC,
    hash: Hashes.SHA256
})

test('Hash > match hashes with same message', async() => {
    const message = 'Chomik'
    const hash1 = await cryptoService.createHash(message)
    const hash2 = await cryptoService.createHash(message)
    expect(hash1).toMatch(hash2)
})

test('Hash > not match hashes with different message', async() => {
    const message1 = 'Chomik1'
    const message2 = 'Chomik2'

    const hash1 = await cryptoService.createHash(message1)
    const hash2 = await cryptoService.createHash(message2)
    expect(hash1).not.toMatch(hash2)
})

test('Hash > switch hash', async() => {
    cryptoService.hash = Hashes.RIPEMD_60
    expect(cryptoService.hash).toMatch(Hashes.RIPEMD_60)

    cryptoService.hash = Hashes.SHA256
    expect(cryptoService.hash).toMatch(Hashes.SHA256)
})

test('Salt > salt text and match it', async() => {
    const text = 'Chomcio'
	const saltedText = await cryptoService.generateSalt(16, text)
	const match = await cryptoService.matchSalt(saltedText, text)

    expect(match).toBe(true)
})

test('Salt > salt text and not match it', async() => {
    const text = 'Chomcio'
    const wrongText = 'Chomcio2'

	const saltedText = await cryptoService.generateSalt(16, text)
	const match = await cryptoService.matchSalt(saltedText, wrongText)

    expect(match).toBe(false)
})

test('HMAC > match HMACs with same message and password', async() => {
    const message = 'Chomik'
    const password = 'chomik123'

    const hmac1 = await cryptoService.createHmac(message, password)
    const hmac2 = await cryptoService.createHmac(message, password)
    expect(hmac1).toMatch(hmac2)
})

test('HMAC > not match HMACs with different message and same password', async() => {
    const message1 = 'Chomik1'
    const message2 = 'Chomik2'
    const password = 'chomik123'

    const hmac1 = await cryptoService.createHmac(message1, password)
    const hmac2 = await cryptoService.createHmac(message2, password)
    expect(hmac1).not.toMatch(hmac2)
})

test('HMAC > not match HMACs with same message and different password', async() => {
    const message = 'Chomik'
    const password1 = 'chomik123'
    const password2 ='321kimohc'

    const hmac1 = await cryptoService.createHmac(message, password1)
    const hmac2 = await cryptoService.createHmac(message, password2)
    expect(hmac1).not.toMatch(hmac2)
})

test('Symmetric Encryption > encrypt and decrypt message', async() => {
    const message = 'Chomik'
    const encryptedMessage = await cryptoService.symmetricEncrypt(message)
	const decryptedMessage = await cryptoService.symmetricDecrypt(encryptedMessage)

    expect(decryptedMessage).toMatch(message)
})

test('Symmetric Encryption > switch algorithm', async() => {
    cryptoService.algorithm = Algorithms.AES_192_CBC
    expect(cryptoService.securityKey.toString('hex').length).toEqual(randomBytes(24).toString('hex').length)


    cryptoService.algorithm = Algorithms.AES_128_CBC
    expect(cryptoService.securityKey.toString('hex').length).toEqual(randomBytes(16).toString('hex').length)
})

test('Keypairs > generate private and public keys', async() => {
    const modulusLength = 2048
    const {
        privateKey, publicKey
    } = await cryptoService.generateKeyPair(modulusLength)

    expect(privateKey).toContain('-----BEGIN PRIVATE KEY-----')
    expect(publicKey).toContain('-----BEGIN PUBLIC KEY-----')
})

test('Asymmetric Encryption > encrypt and decrypt message', async() => {
    const message = 'Chomster'
    const modulusLength = 2048
    const {
        privateKey, publicKey
    } = await cryptoService.generateKeyPair(modulusLength)
    const encryptedMessage = await cryptoService.publicEncrypt(publicKey, message)
	const decryptedMessage = await cryptoService.privateDecrypt(privateKey, encryptedMessage)

    expect(decryptedMessage.toString()).toMatch(message)
})

test('Asymmetric Encryption > throw on 2 keys from different pair', async() => {
    const message = 'Chomster'
    const modulusLength = 2048
    const {
        publicKey: publicKey1
    } = await cryptoService.generateKeyPair(modulusLength)
    const {
        privateKey: privateKey2
    } = await cryptoService.generateKeyPair(modulusLength)
    
    const encryptedMessage = await cryptoService.publicEncrypt(publicKey1, message)

    await expect(cryptoService.privateDecrypt(privateKey2, encryptedMessage)).rejects.toThrow()
})


test('Signing > sign and verify', async() => {
    const {
        privateKey, publicKey
    } = await cryptoService.generateKeyPair(2048)
    
    const data = 'homster to be signed'
    const signature = await cryptoService.sign(data, privateKey)
    const verified = await cryptoService.verify(data, publicKey, signature)
    expect(verified).toBe(true)
})

test('Signing > sign and verify with keys from 2 pairs', async() => {
    const {
        privateKey: privateKey1,
    } = await cryptoService.generateKeyPair(2048)
    const {
        publicKey: publicKey2,
    } = await cryptoService.generateKeyPair(2048)
    
    const data = 'homster to be signed'
    const signature = await cryptoService.sign(data, privateKey1)
    const verified = await cryptoService.verify(data, publicKey2, signature)
    expect(verified).toBe(false)
})