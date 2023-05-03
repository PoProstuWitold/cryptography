import crypto, { createHash, createHmac, generateKeyPairSync, privateDecrypt, publicEncrypt } from 'node:crypto'
import { Algorithms, Hashes } from './constans'

interface Cryptography {
    algorithm: Algorithms
    hash: Hashes
}

export class CryptographyService {
    readonly initVector: Buffer
    public securityKey: Buffer
    private _algorithm: Algorithms
    private _hash: Hashes

    constructor(options: Cryptography) {
        this._hash = options.hash
        this._algorithm = options.algorithm
        
        this.initVector = crypto.randomBytes(16)
        this.securityKey = this.generateSecurityKey(this.algorithm)
    }

    public async symmetricEncrypt(message: string) {
        const cipher = crypto.createCipheriv(this._algorithm, this.securityKey, this.initVector)
        let encryptedData = cipher.update(message, 'utf-8', 'hex')

        encryptedData += cipher.final('hex')

        return encryptedData
    }

    public async symmetricDecrypt(encryptedData: string) {
        const decipher = crypto.createDecipheriv(this._algorithm, this.securityKey, this.initVector)
        let decryptedData = decipher.update(encryptedData, 'hex', 'utf-8')

        decryptedData += decipher.final('utf-8')

        return decryptedData
    }

    private generateSecurityKey(algorithm: Algorithms) {
        switch (algorithm) {
            case Algorithms.AES_256_CBC:
                return crypto.randomBytes(32)
            case Algorithms.AES_192_CBC:
                return crypto.randomBytes(24)
            case Algorithms.AES_128_CBC:
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
            },
        })
        return {
            privateKey, publicKey
        }
    }

    public async publicEncrypt(publicKey: string, message: string) {
        return publicEncrypt(
            publicKey,
            Buffer.from(message)
        )
    }

    public async privateDecrypt(privateKey: string, encryptedMessage: Buffer) {
        return privateDecrypt(
            privateKey,
            encryptedMessage
        )
    }

    get hash() {
        return this._hash
    }

    set hash(hash: Hashes) {
        this._hash = hash
    }

    get algorithm() {
        return this._algorithm
    }

    set algorithm(algorithm: Algorithms) {
        this.securityKey = this.generateSecurityKey(algorithm)
        this._algorithm = algorithm
    }
}