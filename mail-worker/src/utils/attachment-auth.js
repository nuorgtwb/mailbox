const encoder = new TextEncoder();
const URL_TTL_SECONDS = 60 * 60;

const base64url = (input) => {
	const bytes = new Uint8Array(input);
	return btoa(String.fromCharCode(...bytes))
		.replaceAll('=', '')
		.replaceAll('+', '-')
		.replaceAll('/', '_');
};

const attachmentAuth = {
	async signature(c, key, userId, emailId, expires) {
		const secret = c.env.jwt_secret;
		if (!secret) return null;
		const cryptoKey = await crypto.subtle.importKey(
			'raw',
			encoder.encode(secret),
			{ name: 'HMAC', hash: 'SHA-256' },
			false,
			['sign']
		);
		const payload = `${key}|${userId}|${emailId}|${expires}`;
		return base64url(await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(payload)));
	},

	async createUrl(c, attachment) {
		if (!attachment?.key || !attachment.key.startsWith('attachments/')) return null;
		const expires = Math.floor(Date.now() / 1000) + URL_TTL_SECONDS;
		const userId = Number(attachment.userId);
		const emailId = Number(attachment.emailId);
		if (!Number.isSafeInteger(userId) || userId <= 0 || !Number.isSafeInteger(emailId) || emailId <= 0) return null;
		const sig = await this.signature(c, attachment.key, userId, emailId, expires);
		if (!sig) return null;
		const query = new URLSearchParams({ uid: String(userId), eid: String(emailId), exp: String(expires), sig });
		return `/attachments/${attachment.key}?${query.toString()}`;
	},

	async verify(c, key, searchParams) {
		if (!key || !key.startsWith('attachments/') || key.includes('..') || key.includes(String.fromCharCode(92))) return false;
		const userId = Number(searchParams.get('uid'));
		const emailId = Number(searchParams.get('eid'));
		const expires = Number(searchParams.get('exp'));
		const supplied = searchParams.get('sig');
		const now = Math.floor(Date.now() / 1000);
		if (!Number.isSafeInteger(userId) || userId <= 0 ||
			!Number.isSafeInteger(emailId) || emailId <= 0 ||
			!Number.isSafeInteger(expires) || expires < now || expires > now + URL_TTL_SECONDS ||
			!supplied) return false;

		const cryptoKey = await crypto.subtle.importKey(
			'raw',
			encoder.encode(c.env.jwt_secret),
			{ name: 'HMAC', hash: 'SHA-256' },
			false,
			['verify']
		);
		const signatureBytes = Uint8Array.from(
			atob(supplied.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - supplied.length % 4) % 4)),
			char => char.charCodeAt(0)
		);
		const payload = `${key}|${userId}|${emailId}|${expires}`;
		const valid = await crypto.subtle.verify('HMAC', cryptoKey, signatureBytes, encoder.encode(payload));
		if (!valid) return false;

		const row = await c.env.db.prepare(
			'SELECT 1 AS authorized FROM attachments WHERE key = ? AND user_id = ? AND email_id = ? LIMIT 1'
		).bind(key, userId, emailId).first();
		return !!row;
	}
};

export default attachmentAuth;
