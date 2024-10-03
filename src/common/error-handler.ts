import { logger } from './logger'

interface BaseErrorOptions {
	name: string
	description: string
	isOperational: boolean
}

export class BaseError extends Error {
	public readonly name: string
	public readonly isOperational: boolean

	constructor(options: BaseErrorOptions) {
		super(options.description)
		Object.setPrototypeOf(this, new.target.prototype)

		this.name = options.name
		this.isOperational = options.isOperational

		Error.captureStackTrace(this)
	}
}

export class ErrorHandler {
	constructor() {
		process.on('uncaughtException', (err: Error) => {
			this.handleError(err)
		})
		process.on('unhandledRejection', (reason: unknown) => {
			throw reason
		})
	}

	public async handleError(err: Error): Promise<void> {
		if (err.name && err.message) {
			logger.error(`${err.name}: ${err.message}`)
		} else {
			logger.error(`Error: ${err.message || 'Unknown error'}`, err)
		}
	}

	public isTrustedError(error: Error) {
		if (error instanceof BaseError) {
			return error.isOperational
		}
		return false
	}
}
