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

test('Hash > switch hash', async() => {
    cryptoService.hash = Hashes.RIPEMD_60
    expect(cryptoService.hash).toMatch(Hashes.RIPEMD_60)

    cryptoService.hash = Hashes.SHA256
    expect(cryptoService.hash).toMatch(Hashes.SHA256)
})

// test('Salt', async() => {
    
// })

test('HMAC > match HMACs with same message and password', async() => {
    const message = 'Chomik'
    const password = 'chomik123'

    const hmac1 = await cryptoService.createHmac(message, password)
    const hmac2 = await cryptoService.createHmac(message, password)
    expect(hmac1).toMatch(hmac2)
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


// test('Signing', async() => {
    
// })