import app from '../hono/hono';
import { dbInit } from '../init/init';

// Database initialization changes persistent state: accept POST only.
app.post('/init', (c) => {
	return dbInit.init(c);
});
