const argon2 = require('argon2')

async function main() {
	const hash = await argon2.hash('123456')
	console.log('hash:', hash)

	const isValid = await argon2.verify(hash, '123456')
	console.log('isValid:', isValid)
}

main()
.then(console.log)
.catch(console.error)