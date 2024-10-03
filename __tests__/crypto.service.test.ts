import { describe } from 'node:test'
import { strictEqual, notEqual, rejects } from 'node:assert'

import { randomBytes } from 'node:crypto'
import {
    CryptographyService
} from '../src/crypto/crypto.service'
import { Encryptions, Hashes } from '../src/crypto/constans'

const cryptoService = new CryptographyService({
    encryption: Encryptions.AES_256_CBC,
    hash: Hashes.SHA256
})

describe('Hash > match hashes with same message', async() => {
    const message = 'Chomik'
    const hash1 = await cryptoService.createHash(message)
    const hash2 = await cryptoService.createHash(message)
	strictEqual(hash1, hash2)
})

describe('Hash > not match hashes with different message', async() => {
    const message1 = 'Chomik1'
    const message2 = 'Chomik2'

    const hash1 = await cryptoService.createHash(message1)
    const hash2 = await cryptoService.createHash(message2)
	notEqual(hash1, hash2)
})

describe('Hash > switch hash', async() => {
    cryptoService.hash = Hashes.RIPEMD_60
	strictEqual(cryptoService.hash, Hashes.RIPEMD_60)

    cryptoService.hash = Hashes.SHA256
	strictEqual(cryptoService.hash, Hashes.SHA256)
})

describe('Salt > salt text and match it', async() => {
    const text = 'Chomcio'
	const saltedText = await cryptoService.generateSalt(16, text)
	const match = await cryptoService.matchSalt(saltedText, text)

	strictEqual(match, true)
})

describe('Salt > salt text and not match it', async() => {
    const text = 'Chomcio'
    const wrongText = 'Chomcio2'

	const saltedText = await cryptoService.generateSalt(16, text)
	const match = await cryptoService.matchSalt(saltedText, wrongText)

	strictEqual(match, false)
})

describe('HMAC > match HMACs with same message and password', async() => {
    const message = 'Chomik'
    const password = 'chomik123'

    const hmac1 = await cryptoService.createHmac(message, password)
    const hmac2 = await cryptoService.createHmac(message, password)
	strictEqual(hmac1, hmac2)
})

describe('HMAC > not match HMACs with different message and same password', async() => {
    const message1 = 'Chomik1'
    const message2 = 'Chomik2'
    const password = 'chomik123'

    const hmac1 = await cryptoService.createHmac(message1, password)
    const hmac2 = await cryptoService.createHmac(message2, password)
	notEqual(hmac1, hmac2)
})

describe('HMAC > not match HMACs with same message and different password', async() => {
    const message = 'Chomik'
    const password1 = 'chomik123'
    const password2 ='321kimohc'

    const hmac1 = await cryptoService.createHmac(message, password1)
    const hmac2 = await cryptoService.createHmac(message, password2)
	notEqual(hmac1, hmac2)
})

describe('Symmetric Encryption > encrypt and decrypt message', async() => {
	const cryptoService = new CryptographyService({
		encryption: Encryptions.AES_192_CBC,
		hash: Hashes.SHA256,
	})
	
    const message = 'Chomik'
    const encryptedMessage = await cryptoService.symmetricEncrypt(message)
	const decryptedMessage = await cryptoService.symmetricDecrypt(encryptedMessage)
	
	strictEqual(decryptedMessage, message)
})

describe('Symmetric Encryption > switch algorithm', async() => {
    cryptoService.algorithm = Encryptions.AES_192_CBC
	strictEqual(cryptoService.securityKey.toString('hex').length, randomBytes(24).toString('hex').length)


    cryptoService.algorithm = Encryptions.AES_128_CBC
	strictEqual(cryptoService.securityKey.toString('hex').length, randomBytes(16).toString('hex').length)
})

describe('Keypairs > generate private and public keys', async() => {
    const modulusLength = 2048
    const {
        privateKey, publicKey
    } = await cryptoService.generateKeyPair(modulusLength)

	strictEqual(privateKey.includes('-----BEGIN PRIVATE KEY-----'), true)
	strictEqual(publicKey.includes('-----BEGIN PUBLIC KEY-----'), true)
})

describe('Asymmetric Encryption > encrypt and decrypt message', async() => {
    const message = 'Chomster'
    const modulusLength = 2048
    const {
        privateKey, publicKey
    } = await cryptoService.generateKeyPair(modulusLength)
    const encryptedMessage = await cryptoService.publicEncrypt(publicKey, message)
	const decryptedMessage = await cryptoService.privateDecrypt(privateKey, encryptedMessage)

	strictEqual(decryptedMessage.toString(), message)
})

describe('Asymmetric Encryption > throw on 2 keys from different pair', async() => {
    const message = 'Chomster'
    const modulusLength = 2048
    const {
        publicKey: publicKey1
    } = await cryptoService.generateKeyPair(modulusLength)
    const {
        privateKey: privateKey2
    } = await cryptoService.generateKeyPair(modulusLength)
    
    const encryptedMessage = await cryptoService.publicEncrypt(publicKey1, message)

	await rejects(cryptoService.privateDecrypt(privateKey2, encryptedMessage))
})


describe('Signing > sign and verify', async() => {
    const {
        privateKey, publicKey
    } = await cryptoService.generateKeyPair(2048)
    
    const data = 'homster to be signed'
    const signature = await cryptoService.sign(data, privateKey)
    const verified = await cryptoService.verify(data, publicKey, signature)
	strictEqual(verified, true)
})

describe('Signing > sign and verify with keys from 2 pairs', async() => {
    const {
        privateKey: privateKey1,
    } = await cryptoService.generateKeyPair(2048)
    const {
        publicKey: publicKey2,
    } = await cryptoService.generateKeyPair(2048)
    
    const data = 'homster to be signed'
    const signature = await cryptoService.sign(data, privateKey1)
    const verified = await cryptoService.verify(data, publicKey2, signature)
    strictEqual(verified, false)
})