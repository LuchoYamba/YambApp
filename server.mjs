import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join } from 'node:path';
const root = process.cwd();
const mime = { '.html':'text/html; charset=utf-8', '.css':'text/css; charset=utf-8', '.js':'text/javascript; charset=utf-8', '.svg':'image/svg+xml' };
http.createServer(async (req,res) => {
  try {
    const path = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
    const file = path === '/' ? 'index.html' : path.replace(/^\/+/, '');
    const data = await readFile(join(root, file));
    res.writeHead(200, { 'Content-Type': mime[extname(file)] || 'application/octet-stream' }); res.end(data);
  } catch { res.writeHead(404, {'Content-Type':'text/plain; charset=utf-8'}); res.end('No encontrado'); }
}).listen(Number(process.env.PORT || 4173), '0.0.0.0', () => console.log('YambApp disponible en http://localhost:4173'));
