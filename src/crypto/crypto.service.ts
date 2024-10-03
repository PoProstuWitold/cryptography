import crypto, {
	createHash,
	createHmac,
	createSign,
	createVerify,
	generateKeyPairSync,
	privateDecrypt,
	publicEncrypt,
	randomBytes,
	scryptSync,
	timingSafeEqual
} from 'node:crypto'
import { Encryptions, type Hashes } from './constans'

interface Cryptography {
	encryption: Encryptions
	hash: Hashes
}

export class CryptographyService {
	readonly initVector: Buffer
	public securityKey: Buffer
	private _encryption: Encryptions
	private _hash: Hashes

	constructor(options: Cryptography) {
		this._hash = options.hash
		this._encryption = options.encryption

		this.initVector = crypto.randomBytes(16)
		this.securityKey = this.generateSecurityKey(this.algorithm)
	}

	public async symmetricEncrypt(message: string) {
		const cipher = crypto.createCipheriv(
			this._encryption,
			this.securityKey,
			this.initVector
		)
		let encryptedData = cipher.update(message, 'utf-8', 'hex')

		encryptedData += cipher.final('hex')

		return encryptedData
	}

	public async symmetricDecrypt(encryptedData: string) {
		const decipher = crypto.createDecipheriv(
			this._encryption,
			this.securityKey,
			this.initVector
		)
		let decryptedData = decipher.update(encryptedData, 'hex', 'utf-8')

		decryptedData += decipher.final('utf-8')

		return decryptedData
	}

	private generateSecurityKey(encryptions: Encryptions) {
		switch (encryptions) {
			case Encryptions.AES_256_CBC:
				return crypto.randomBytes(32)
			case Encryptions.AES_192_CBC:
				return crypto.randomBytes(24)
			case Encryptions.AES_128_CBC:
				return crypto.randomBytes(16)
		}
	}

	public async createHash(message: string) {
		return createHash(this.hash).update(message).digest('hex')
	}

	public async createHmac(message: string, password: string) {
		return createHmac(this.hash, password).update(message).digest('hex')
	}

	public async generateKeyPair(modulusLength: number) {
		const { privateKey, publicKey } = generateKeyPairSync('rsa', {
			modulusLength, // the length of your key in bits
			publicKeyEncoding: {
				type: 'spki',
				format: 'pem'
			},
			privateKeyEncoding: {
				type: 'pkcs8',
				format: 'pem'
			}
		})
		return {
			privateKey,
			publicKey
		}
	}

	public async publicEncrypt(publicKey: string, message: string) {
		return publicEncrypt(publicKey, Buffer.from(message))
	}

	public async privateDecrypt(privateKey: string, encryptedMessage: Buffer) {
		return privateDecrypt(privateKey, encryptedMessage)
	}

	public async sign(data: string, privateKey: string) {
		const signer = createSign('rsa-sha256')
		signer.update(data)
		const signature = signer.sign(privateKey, 'hex')
		return signature
	}

	public async verify(data: string, publicKey: string, signature: string) {
		const verifier = createVerify('rsa-sha256')
		verifier.update(data)
		const isVerified = verifier.verify(publicKey, signature, 'hex')
		return isVerified
	}

	public async generateSalt(rounds: number, text: string) {
		const salt = randomBytes(rounds).toString('hex') //
		const hash = scryptSync(text, salt, 64).toString('hex') //
		return `${salt}:${hash}` //
	}

	public async matchSalt(saltedText: string, text: string) {
		const [salt, key] = saltedText.split(':')
		const hashedBuffer = scryptSync(text, salt, 64)

		const keyBuffer = Buffer.from(key, 'hex')
		const match = timingSafeEqual(hashedBuffer, keyBuffer)

		return match
	}

	get hash() {
		return this._hash
	}

	set hash(hash: Hashes) {
		this._hash = hash
	}

	get algorithm() {
		return this._encryption
	}

	set algorithm(encryption: Encryptions) {
		this.securityKey = this.generateSecurityKey(encryption)
		this._encryption = encryption
	}
}
