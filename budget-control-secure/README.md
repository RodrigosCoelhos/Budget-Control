# Budget Control — servidor e base de dados

## Requisitos
Node.js 20+, PostgreSQL 15+ e npm.

## Instalação
1. Criar utilizador e base de dados PostgreSQL (exemplo no `psql`):
   ```sql
   CREATE USER budget WITH PASSWORD 'escolha_uma_password_forte';
   CREATE DATABASE budget_control OWNER budget;
   ```
2. Executar o esquema: `psql -h localhost -U budget -d budget_control -f sql/schema.sql`
3. `cp .env.example .env` e definir `DATABASE_URL` com as credenciais escolhidas. Definir `APP_ORIGIN` exatamente como o endereço do navegador (por exemplo `http://localhost:3000`).
4. `npm install`
5. `npm run init-admin` para criar o primeiro administrador (sem contas administrativas predefinidas).
6. `npm start` e abrir `http://localhost:3000`.

## Regras de segurança
- As sessões são armazenadas no servidor; cookie HttpOnly, SameSite=Strict e Secure em produção.
- A API nunca recebe `owner_id` do cliente ao criar despesas: usa o utilizador autenticado.
- Os endpoints `/api/projects/:id/...` exigem participação ou papel de administrador.
- O resumo financeiro é agregado no servidor e pode incluir despesas de colegas sem revelar os registos individuais.
- A edição/eliminação verifica proprietário, participação atual e permissão; o administrador pode gerir todos os registos.
- `/api/admin/*` exige papel administrativo.
- Os utilizadores recém-registados começam sem projetos; só o administrador pode atribuí-los.
- Para recuperação de conta, configurar SMTP no `.env`; não existe envio de emails sem SMTP.

## Antes de colocar em produção
Usar HTTPS, definir `NODE_ENV=production` e `APP_ORIGIN=https://seu-dominio`, configurar SMTP, backups automáticos, logs e monitorização. Colocar atrás de proxy HTTPS de confiança e não expor PostgreSQL publicamente. Adicionar testes de integração, auditoria das alterações, paginação de despesas e proteção contra tentativas automatizadas distribuídas. A política de segurança de conteúdo está desativada neste exemplo para permitir os estilos inline do protótipo: deve ser reforçada antes da produção.

**Não usar as contas de demonstração `admin/admin123` ou `demo/demo123`: não existem nesta versão.**
