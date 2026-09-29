import { config as loadDotenv } from 'dotenv';
import express from 'express';
import { fileURLToPath } from 'node:url';
import { createSupabaseAdminClient } from './src/config/supabase.js';
import { apiRouter } from './src/routes/index.js';

const dotenvResult = loadDotenv();
for (const name of ['SUPABASE_URL', 'SUPABASE_PUBLISHABLE_KEY', 'SUPABASE_SERVICE_ROLE_KEY']) {
  if (!process.env[name]?.trim() && dotenvResult.parsed?.[name]?.trim()) {
    process.env[name] = dotenvResult.parsed[name];
  }
}

const app = express();
const port = Number(process.env.PORT || 4173);
const host = process.env.HOST || '0.0.0.0';
const publicDirectory = fileURLToPath(new URL('.', import.meta.url));
const supabaseBrowserSdk = fileURLToPath(new URL('./node_modules/@supabase/supabase-js/dist/umd/supabase.js', import.meta.url));

app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));

// Initialize the private server-side client only when its environment variables exist.
// This keeps the current V1 usable before a Supabase project is configured.
app.locals.supabaseAdmin = createSupabaseAdminClient();

app.use('/api', apiRouter);
app.get('/vendor/supabase.js', (req, res, next) => {
  res.sendFile(supabaseBrowserSdk, error => {
    if (error) next(error);
  });
});
app.use((req, res, next) => {
  const path = req.path;
  const privateFile = new Set(['/server.mjs', '/package.json', '/pnpm-lock.yaml']);
  const privateDirectory = ['/src/', '/supabase/', '/node_modules/'];
  if (privateFile.has(path) || privateDirectory.some(prefix => path.startsWith(prefix))) {
    return res.status(404).type('text').send('No encontrado');
  }
  return next();
});
app.use(express.static(publicDirectory, { index: 'index.html' }));

app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ ok: false, error: 'Ruta API no encontrada' });
  }
  return res.status(404).type('text').send('No encontrado');
});

app.use((error, req, res, next) => {
  console.error('Error no controlado:', error);
  if (res.headersSent) return next(error);
  return res.status(error.status || 500).json({
    ok: false,
    error: error.status && error.status < 500 ? error.message : 'Error interno del servidor',
  });
});

app.listen(port, host, () => {
  console.log(`YambApp disponible en http://localhost:${port}`);
});
