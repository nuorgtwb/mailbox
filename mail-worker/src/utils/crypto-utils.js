const encoder = new TextEncoder();
const PBKDF2_ITERATIONS = 120000;
const PBKDF2_PREFIX = 'pbkdf2';

const toBase64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));

const saltHashUtils = {

	generateSalt(length = 16) {
		const array = new Uint8Array(length);
		crypto.getRandomValues(array);
		return btoa(String.fromCharCode(...array));
	},

	async hashPassword(password) {
		const salt = this.generateSalt();
		const hash = await this.genPbkdf2Hash(password, salt, PBKDF2_ITERATIONS);
		return { salt, hash: `${PBKDF2_PREFIX}$${PBKDF2_ITERATIONS}$${hash}` };
	},

	// Retained only to verify existing SHA-256 password hashes during migration.
	async genHashPassword(password, salt) {
		const data = encoder.encode(salt + password);
		const hashBuffer = await crypto.subtle.digest('SHA-256', data);
		return toBase64(hashBuffer);
	},

	async genPbkdf2Hash(password, salt, iterations = PBKDF2_ITERATIONS) {
		const key = await crypto.subtle.importKey(
			'raw',
			encoder.encode(password),
			'PBKDF2',
			false,
			['deriveBits']
		);
		const bits = await crypto.subtle.deriveBits({
			name: 'PBKDF2',
			salt: encoder.encode(salt),
			iterations,
			hash: 'SHA-256'
		}, key, 256);
		return toBase64(bits);
	},

	needsRehash(storedHash) {
		if (typeof storedHash !== 'string' || !storedHash.startsWith(PBKDF2_PREFIX + '$')) {
			return true;
		}
		const iterations = Number(storedHash.split('$')[1]);
		return !Number.isSafeInteger(iterations) || iterations < PBKDF2_ITERATIONS;
	},

	async verifyPassword(inputPassword, salt, storedHash) {
		if (typeof storedHash !== 'string') return false;

		if (storedHash.startsWith(PBKDF2_PREFIX + '$')) {
			const [, iterationsText, expectedHash] = storedHash.split('$');
			const iterations = Number(iterationsText);
			if (!Number.isSafeInteger(iterations) || iterations < 10000 || iterations > 1000000 || !expectedHash) {
				return false;
			}
			const actualHash = await this.genPbkdf2Hash(inputPassword, salt, iterations);
			return actualHash === expectedHash;
		}

		// Backward compatibility: verify legacy SHA-256 hashes, then upgrade on successful login.
		const legacyHash = await this.genHashPassword(inputPassword, salt);
		return legacyHash === storedHash;
	},

	genRandomPwd(length = 8) {
		const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		const maxByte = 256 - (256 % chars.length);
		let result = '';
		while (result.length < length) {
			const bytes = new Uint8Array(Math.max(16, length - result.length));
			crypto.getRandomValues(bytes);
			for (const byte of bytes) {
				if (byte >= maxByte) continue;
				result += chars[byte % chars.length];
				if (result.length === length) break;
			}
		}
		return result;
	}
};

export default saltHashUtils;
