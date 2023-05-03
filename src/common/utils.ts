export function loggedMethod(headMessage = 'LOG:') {
    return function actualDecorator(originalMethod: any, context: ClassMethodDecoratorContext) {
        const methodName = String(context.name)
        function replacementMethod(this: any, ...args: any[]) {
            console.log(`${headMessage} Entering method '${methodName}'.`)
            const result = originalMethod.call(this, ...args)
            console.log(`${headMessage} Exiting method '${methodName}'.`)
            return result
        }
        return replacementMethod
    }
}

export const isProduction = () => process.env.NODE_ENV === 'production' ? true : false