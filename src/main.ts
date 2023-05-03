import { CryptographyService } from './crypto/crypto.service'
import { ErrorHandler } from './common/error-handler'
import { Algorithms, Hashes } from './crypto/constans'

async function main() {
	try {
		new ErrorHandler()

		const cryptoService = new CryptographyService({
			algorithm: Algorithms.AES_192_CBC,
			hash: Hashes.SHA256,
		})


		// Symmetric Encryption
		const encryptedMessage1 = await cryptoService.symmetricEncrypt('Hellooo')
		const decryptedMessage1 = await cryptoService.symmetricDecrypt(encryptedMessage1)
		console.table([
			{
				'algorithm': cryptoService.algorithm,
				'symmetricEncrypt': encryptedMessage1,
				'symmetricDecrypt': decryptedMessage1
			}
		])

		// Hash
		const hash = await cryptoService.createHash('chomik123!')
		console.table([
			{
				'hash algorithm': cryptoService.hash,
				'createHash': hash,
				'plain': 'chomik123!'
			}
		])

		// HMAC
		const hmac = await cryptoService.createHmac('chomcio123!', 'secret_hamster')
		console.table([
			{
				'hash algorithm': cryptoService.hash,
				'createHmac': hmac,
				'plain': 'chomik123!',
				'hmac password': 'secret_hamster'
			}
		])

		// Keypairs (RSA)
		const { 
			privateKey: privateKey1, 
			publicKey: publicKey1  
		} = await cryptoService.generateKeyPair(2048)

		// Asymmetric Encryption (RSA)
		const encryptedMessage2 = await cryptoService.publicEncrypt(publicKey1, 'Chomster')
		const decryptedMessage2 = await cryptoService.privateDecrypt(privateKey1, encryptedMessage2)
		console.log('publicEncrypt', encryptedMessage2.toString('hex'), '\n')
		console.log('privateDecrypt', decryptedMessage2.toString())

		// Signing
		const {
			privateKey, publicKey
		} = await cryptoService.generateKeyPair(2048)

		const data = 'homster to be signed'
		const signature = await cryptoService.sign(data, privateKey)
		const verified = await cryptoService.verify(data, publicKey, signature)
		console.log(verified)

	} catch (err) {
		throw err
	}
}

void main()