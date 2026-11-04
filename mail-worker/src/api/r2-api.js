import r2Service from '../service/r2-service';
import app from '../hono/hono';
import attachmentAuth from '../utils/attachment-auth';

app.get('/oss/*', async (c) => {
	const key = c.req.path.split('/oss/')[1];
	if (key.startsWith('attachments/') && !await attachmentAuth.verify(c, key, new URL(c.req.url).searchParams)) {
		return c.text('Forbidden', 403);
	}
	const resp = await r2Service.toObjResp(c, key);
	if (!resp) {
		return c.notFound();
	}
	return resp;
});


