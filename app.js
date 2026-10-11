/* DEMONSTRAÇÃO LOCAL: localStorage NÃO é um sistema seguro de autenticação nem de autorização. */
const $ = (s) => document.querySelector(s),
  app = $("#app");
const esc = (v) =>
  String(v ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const eur = (n) =>
  new Intl.NumberFormat("pt-PT", {
    style: "currency",
    currency: "EUR",
    maximumFractionDigits: 0,
  }).format(Number(n) || 0);
const seed = {
  users: [
    {
      id: "admin",
      name: "Administrador",
      email: "admin@demo.local",
      password: "admin123",
      role: "admin",
      permissions: { create: true, edit: true, delete: true },
    },
    {
      id: "demo",
      name: "Utilizador Demo",
      email: "demo@demo.local",
      password: "demo123",
      role: "user",
      permissions: { create: true, edit: true, delete: true },
    },
  ],
  projects: [
    { id: "erp", name: "Implementação ERP", budget: 150000, members: ["demo"] },
    { id: "site", name: "Novo Website", budget: 45000, members: [] },
  ],
  expenses: [
    {
      id: "e1",
      owner: "demo",
      project: "erp",
      title: "Licenças de software",
      category: "Software",
      amount: 18500,
      method: "Cartão",
      date: "2026-10-01",
    },
    {
      id: "e2",
      owner: "admin",
      project: "erp",
      title: "Consultoria externa",
      category: "Serviços",
      amount: 32000,
      method: "Transferência",
      date: "2026-10-03",
    },
    {
      id: "e3",
      owner: "demo",
      project: "erp",
      title: "Equipamentos",
      category: "Hardware",
      amount: 12500,
      method: "Cartão",
      date: "2026-10-05",
    },
  ],
};
let db;
try {
  db = JSON.parse(localStorage.getItem("bc_demo_v3")) || structuredClone(seed);
} catch {
  db = structuredClone(seed);
}
let session = sessionStorage.getItem("bc_session"),
  tab = "dashboard",
  project = "erp",
  search = "",
  category = "",
  adminUserFilter = "",
  adminProjectFilter = "";
function save() {
  localStorage.setItem("bc_demo_v3", JSON.stringify(db));
}
function me() {
  return db.users.find((u) => u.id === session);
}
function admin() {
  return me()?.role === "admin";
}
function allowed(action) {
  return admin() || !!me()?.permissions[action];
}
function projectsForMe() {
  return db.projects.filter(
    (p) => admin() || (p.members || []).includes(session),
  );
}
function canAccessProject(id) {
  return admin() || projectsForMe().some((p) => p.id === id);
}
function visible() {
  return db.expenses.filter(
    (e) =>
      e.project === project &&
      canAccessProject(e.project) &&
      (admin() || e.owner === session),
  );
}
function userName(id) {
  return db.users.find((u) => u.id === id)?.name || "Utilizador";
}
function projectName(id) {
  return db.projects.find((p) => p.id === id)?.name || "Projeto removido";
}
function projectExpenses(id) {
  return db.expenses.filter((e) => e.project === id && canAccessProject(id));
}
function allUserExpenses(id, projectId = "") {
  if (!admin()) return [];
  return db.expenses.filter(
    (e) => (!id || e.owner === id) && (!projectId || e.project === projectId),
  );
}
function notice(s, bad = false) {
  const n = $("#notice");
  if (n) {
    n.textContent = s;
    n.className = "notice" + (bad ? " error" : "");
    n.hidden = false;
  }
}
function auth(mode = "login") {
  let titles = {
    login: "Iniciar sessão",
    register: "Criar conta",
    recover: "Recuperar utilizador",
    reset: "Recuperar palavra-passe",
  };
  app.innerHTML = `<div class="auth"><div class="brand"><span class="logo">▥</span><div><b>BudgetControl</b><div class="sub">Gestão de orçamentos e despesas</div></div></div><h1>${titles[mode]}</h1><div class="notice">Protótipo local: admin / admin123 ou demo / demo123. Não utilize palavras-passe reais.</div><div id="notice" hidden></div><form id="authform">${mode === "register" ? '<label>Nome completo<input name="name" required></label>' : ""}${mode !== "login" && mode !== "register" ? '<label>Email da conta<input name="email" type="email" required></label>' : `<label>Utilizador ou email<input name="login" required></label><label>Palavra-passe<input name="password" type="password" minlength="6" required></label>${mode === "register" ? '<label>Email<input name="email" type="email" required></label>' : ""}`}<button class="primary">${titles[mode]}</button></form><div class="links"><button data-auth="login">Entrar</button><button data-auth="register">Criar conta</button><button data-auth="recover">Esqueci o utilizador</button><button data-auth="reset">Esqueci a palavra-passe</button></div></div>`;
  $$("[data-auth]").forEach((b) => (b.onclick = () => auth(b.dataset.auth)));
  $("#authform").onsubmit = (e) => {
    e.preventDefault();
    let f = Object.fromEntries(new FormData(e.target));
    if (mode === "login") {
      let u = db.users.find(
        (x) =>
          (x.id === f.login || x.email === f.login) &&
          x.password === f.password,
      );
      if (!u) return notice("Credenciais incorretas.", true);
      session = u.id;
      sessionStorage.setItem("bc_session", session);
      render();
    } else if (mode === "register") {
      let id = f.login.trim().toLowerCase();
      if (db.users.some((u) => u.id === id || u.email === f.email))
        return notice("Utilizador ou email já existente.", true);
      db.users.push({
        id,
        name: f.name,
        email: f.email,
        password: f.password,
        role: "user",
        permissions: { create: true, edit: true, delete: true },
      });
      save();
      notice("Conta criada. Clique em Entrar para iniciar sessão.");
    } else {
      notice(
        "Nesta demonstração, a recuperação por email está desativada. Em produção será feita por ligação temporária enviada por email.",
      );
    }
  };
}
function $$(s) {
  return [...document.querySelectorAll(s)];
}
function render() {
  if (!me()) return auth();
  let available = projectsForMe();
  if (!available.some((p) => p.id === project))
    project = available[0]?.id || null;
  let p = available.find((x) => x.id === project);
  if (!p) {
    app.innerHTML =
      '<div class="auth"><h1>Sem projetos atribuídos</h1><p>Peça ao administrador para o adicionar a um projeto.</p><button id="logout">Sair</button></div>';
    $("#logout").onclick = () => {
      session = null;
      sessionStorage.removeItem("bc_session");
      auth();
    };
    return;
  }
  let list = visible(),
    projectList = projectExpenses(project),
    spent = projectList.reduce((a, e) => a + Number(e.amount), 0);
  let pct = p.budget ? (spent / p.budget) * 100 : 0;
  app.innerHTML = `<div class="shell"><header class="top"><div class="brand"><span class="logo">▥</span><div><b>BudgetControl</b><div class="sub">Gestão de orçamento</div></div></div><div class="top-actions"><span class="pill">${admin() ? "Administrador" : "Utilizador"}</span><button id="logout">Sair</button></div></header><div class="toolbar"><label><span class="smalllabel">Projeto atual</span><select id="project">${available.map((x) => `<option value="${esc(x.id)}" ${x.id === project ? "selected" : ""}>${esc(x.name)}</option>`).join("")}</select></label><button class="primary" id="new" ${!allowed("create") ? "disabled" : ""}>＋ Nova despesa</button></div><div class="metrics"><div class="metric"><span>Budget total</span><strong>${eur(p.budget)}</strong></div><div class="metric"><span>Despesas totais do projeto</span><strong>${eur(spent)}</strong></div><div class="metric"><span>Saldo disponível</span><strong class="${p.budget - spent >= 0 ? "green" : ""}">${eur(p.budget - spent)}</strong></div><div class="metric"><span>Budget utilizado</span><strong>${pct.toFixed(1)}%</strong></div></div><div class="progress-head"><b>Consumo do budget</b><span class="muted">${eur(spent)} / ${eur(p.budget)}</span></div><div class="progress"><div class="fill" style="width:${Math.max(0, Math.min(100, pct))}%"></div></div><div class="tabs"><button data-tab="dashboard" class="${tab === "dashboard" ? "active" : ""}">Dashboard</button><button data-tab="expenses" class="${tab === "expenses" ? "active" : ""}">Despesas</button>${admin() ? `<button data-tab="admin" class="${tab === "admin" ? "active" : ""}">Administração</button>` : ""}</div><div id="content"></div></div><div id="overlay"></div>`;
  $("#logout").onclick = () => {
    session = null;
    sessionStorage.removeItem("bc_session");
    auth();
  };
  $("#project").onchange = (e) => {
    project = e.target.value;
    render();
  };
  $("#new").onclick = () => expenseModal();
  $$("[data-tab]").forEach(
    (b) =>
      (b.onclick = () => {
        tab = b.dataset.tab;
        render();
      }),
  );
  if (tab === "dashboard") dashboard(projectList);
  else if (tab === "expenses") expenses(list);
  else if (admin()) administration();
}
function dashboard(list) {
  let groups = ["Hardware", "Serviços", "Software", "Outros"],
    colors = ["#ff681e", "#9045f5", "#0d86fa", "#a3a3a3"],
    totals = groups.map((c) =>
      list
        .filter((e) => e.category === c)
        .reduce((a, e) => a + Number(e.amount), 0),
    ),
    sum = totals.reduce((a, b) => a + b, 0),
    at = 0,
    stops = totals
      .map((n, i) => {
        let from = at;
        at += sum ? (n / sum) * 100 : 0;
        return `${colors[i]} ${from}% ${at}%`;
      })
      .join(",");
  $("#content").innerHTML =
    `<div class="section-title">Despesas por categoria</div><div class="chartbox">${sum ? `<div class="donut" style="background:conic-gradient(${stops})"></div>` : '<div class="empty">Ainda não existem despesas neste projeto.</div>'}<div class="legend">${groups.map((g, i) => `<span><i class="dot" style="background:${colors[i]}"></i>${g} (${eur(totals[i])})</span>`).join("")}</div><p class="muted" style="text-align:left;margin-top:25px">Distribuição das despesas registadas</p></div>`;
}
function expenses(list) {
  let filtered = list.filter(
    (e) =>
      (e.title.toLowerCase().includes(search.toLowerCase()) ||
        e.method.toLowerCase().includes(search.toLowerCase())) &&
      (!category || e.category === category),
  );
  $("#content").innerHTML =
    `<div class="section-title">Despesas registadas <span class="pill">${filtered.length} registos</span></div><div class="filters"><input id="search" placeholder="Pesquisar despesas" value="${esc(search)}"><select id="cat"><option value="">Todas as categorias</option>${["Hardware", "Serviços", "Software", "Outros"].map((c) => `<option ${category === c ? "selected" : ""}>${c}</option>`).join("")}</select></div><div id="records"></div>`;
  $("#search").oninput = (e) => {
    search = e.target.value;
    expenses(visible());
    $("#search").focus();
    $("#search").setSelectionRange(search.length, search.length);
  };
  $("#cat").onchange = (e) => {
    category = e.target.value;
    expenses(visible());
  };
  $("#records").innerHTML = filtered.length
    ? filtered
        .map(
          (e) =>
            `<article class="expense"><div><strong>${esc(e.title)}</strong><div class="muted">${esc(e.category)} · ${admin() ? esc(userName(e.owner)) : e.owner === session ? "Eu" : "Outro utilizador"} · ${esc(e.date)}</div></div><div class="right"><b>${eur(e.amount)}</b>${(admin() || e.owner === session) && (allowed("edit") || allowed("delete")) ? `<div class="actions">${allowed("edit") ? `<button data-edit="${esc(e.id)}">✎ Editar</button>` : ""}${allowed("delete") ? `<button class="danger" data-delete="${esc(e.id)}">♜ Excluir</button>` : ""}</div>` : ""}</div></article>`,
        )
        .join("")
    : '<div class="empty">Nenhuma despesa encontrada.</div>';
  $$("[data-edit]").forEach(
    (b) => (b.onclick = () => expenseModal(b.dataset.edit)),
  );
  $$("[data-delete]").forEach(
    (b) =>
      (b.onclick = () => {
        let x = db.expenses.find((e) => e.id === b.dataset.delete);
        if (
          !x ||
          !canAccessProject(x.project) ||
          (!admin() && x.owner !== session) ||
          !allowed("delete")
        )
          return;
        if (confirm("Eliminar esta despesa?")) {
          db.expenses = db.expenses.filter((e) => e.id !== x.id);
          save();
          render();
        }
      }),
  );
}
function expenseModal(id) {
  let x = id ? db.expenses.find((e) => e.id === id) : null;
  if (
    !canAccessProject(project) ||
    (x &&
      (!canAccessProject(x.project) ||
        (!admin() && x.owner !== session) ||
        !allowed("edit"))) ||
    (!x && !allowed("create"))
  )
    return;
  $("#overlay").innerHTML =
    `<div class="modal-bg"><div class="modal"><h2>${x ? "Editar despesa" : "Nova despesa"}</h2><form id="expenseform"><label>Descrição<input name="title" required maxlength="120" value="${esc(x?.title || "")}"></label><label>Categoria<select name="category">${["Hardware", "Serviços", "Software", "Outros"].map((c) => `<option ${x?.category === c ? "selected" : ""}>${c}</option>`).join("")}</select></label><label>Valor (€)<input name="amount" type="number" min="0.01" step="0.01" required value="${x?.amount || ""}"></label><label>Data<input name="date" type="date" required value="${esc(x?.date || new Date().toISOString().slice(0, 10))}"></label><label>Método de pagamento<input name="method" required value="${esc(x?.method || "Cartão")}"></label><div class="modal-actions"><button type="button" id="cancel">Cancelar</button><button class="primary">Guardar</button></div></form></div></div>`;
  $("#cancel").onclick = () => ($("#overlay").innerHTML = "");
  $("#expenseform").onsubmit = (e) => {
    e.preventDefault();
    let f = Object.fromEntries(new FormData(e.target));
    let data = {
      title: f.title.trim(),
      category: f.category,
      amount: Number(f.amount),
      date: f.date,
      method: f.method.trim(),
    };
    if (!data.title || !data.method || !(data.amount > 0)) return;
    if (x) Object.assign(x, data);
    else
      db.expenses.push({
        id: crypto.randomUUID(),
        owner: session,
        project,
        ...data,
      });
    save();
    if (!admin() || tab !== "admin") tab = "expenses";
    render();
  };
}
function administration() {
  if (!admin()) return;
  const users = db.users.filter((u) => u.role !== "admin");
  const filtered = allUserExpenses(adminUserFilter, adminProjectFilter).sort(
    (a, b) => b.date.localeCompare(a.date),
  );
  const total = filtered.reduce((n, e) => n + Number(e.amount), 0);
  $("#content").innerHTML =
    `<div class="section-title">Consulta administrativa de despesas</div>
<p class="muted">Selecione um utilizador e, opcionalmente, um projeto. Só os administradores podem consultar despesas de terceiros.</p>
<div class="filters"><label>Utilizador<select id="admin-user"><option value="">Todos os utilizadores</option>${db.users.map((u) => `<option value="${esc(u.id)}" ${adminUserFilter === u.id ? "selected" : ""}>${esc(u.name)}</option>`).join("")}</select></label><label>Projeto<select id="admin-project"><option value="">Todos os projetos</option>${db.projects.map((p) => `<option value="${esc(p.id)}" ${adminProjectFilter === p.id ? "selected" : ""}>${esc(p.name)}</option>`).join("")}</select></label></div>
<div class="admin-summary"><div><span class="muted">Despesas encontradas</span><strong>${filtered.length}</strong></div><div><span class="muted">Valor total</span><strong>${eur(total)}</strong></div></div>
<div class="section-title">Despesas por utilizador <span class="pill">${filtered.length} registos</span></div>
${filtered.length ? filtered.map((e) => `<article class="expense"><div><strong>${esc(e.title)}</strong><div class="muted">${esc(userName(e.owner))} · ${esc(projectName(e.project))}</div><div class="muted">${esc(e.category)} · ${esc(e.date)} · ${esc(e.method)}</div></div><div class="right"><b>${eur(e.amount)}</b><div class="actions"><button data-admin-edit="${esc(e.id)}">✎ Editar</button><button class="danger" data-admin-delete="${esc(e.id)}">Excluir</button></div></div></article>`).join("") : '<div class="empty">Nenhuma despesa corresponde aos filtros.</div>'}
<div class="section-title">Gestão de utilizadores e permissões</div>
<p class="muted">As permissões são globais para cada utilizador nesta demonstração. Um participante só pode alterar as suas próprias despesas.</p>
${users
  .map(
    (u) =>
      `<div class="admin-card"><div class="titleline"><b>${esc(u.name)} (${esc(u.id)})</b><span class="muted">${esc(u.email)}</span></div><div class="checkrow">${[
        ["create", "Criar"],
        ["edit", "Editar"],
        ["delete", "Eliminar"],
      ]
        .map(
          ([k, label]) =>
            `<label><input type="checkbox" data-user="${esc(u.id)}" data-permission="${k}" ${u.permissions[k] ? "checked" : ""}>${label}</label>`,
        )
        .join(
          "",
        )}</div><div class="muted">Despesas registadas: ${db.expenses.filter((e) => e.owner === u.id).length} · <button data-view-user="${esc(u.id)}">Ver todas as despesas</button></div></div>`,
  )
  .join("")}
<div class="section-title">Projetos e participantes</div>
${db.projects.map((p) => `<div class="admin-card"><b>${esc(p.name)}</b> — ${eur(p.budget)} <button data-budget="${esc(p.id)}">Alterar orçamento</button><div class="muted">Participantes autorizados:</div><div class="checkrow">${users.map((u) => `<label><input type="checkbox" data-member-project="${esc(p.id)}" data-member-user="${esc(u.id)}" ${(p.members || []).includes(u.id) ? "checked" : ""}>${esc(u.name)}</label>`).join("")}</div></div>`).join("")}<button id="addproject">＋ Novo projeto</button>`;
  $("#admin-user").onchange = (e) => {
    adminUserFilter = e.target.value;
    administration();
  };
  $("#admin-project").onchange = (e) => {
    adminProjectFilter = e.target.value;
    administration();
  };
  $$("[data-view-user]").forEach(
    (b) =>
      (b.onclick = () => {
        adminUserFilter = b.dataset.viewUser;
        adminProjectFilter = "";
        administration();
        $("#admin-user").scrollIntoView({
          behavior: "smooth",
          block: "center",
        });
      }),
  );
  $$("[data-admin-edit]").forEach(
    (b) => (b.onclick = () => expenseModal(b.dataset.adminEdit)),
  );
  $$("[data-admin-delete]").forEach(
    (b) =>
      (b.onclick = () => {
        const x = db.expenses.find((e) => e.id === b.dataset.adminDelete);
        if (!admin() || !x) return;
        if (confirm("Eliminar esta despesa?")) {
          db.expenses = db.expenses.filter((e) => e.id !== x.id);
          save();
          render();
        }
      }),
  );
  $$("[data-permission]").forEach(
    (b) =>
      (b.onchange = () => {
        let u = db.users.find((u) => u.id === b.dataset.user);
        if (u && u.role !== "admin") {
          u.permissions[b.dataset.permission] = b.checked;
          save();
        }
      }),
  );
  $$("[data-member-project]").forEach(
    (b) =>
      (b.onchange = () => {
        let p = db.projects.find((x) => x.id === b.dataset.memberProject);
        if (!p) return;
        p.members = p.members || [];
        p.members = p.members.filter((id) => id !== b.dataset.memberUser);
        if (b.checked) p.members.push(b.dataset.memberUser);
        save();
      }),
  );
  $$("[data-budget]").forEach(
    (b) =>
      (b.onclick = () => {
        let p = db.projects.find((x) => x.id === b.dataset.budget),
          n = prompt("Novo orçamento em euros:", p.budget);
        if (n !== null && Number(n) >= 0 && n.trim() !== "") {
          p.budget = Number(n);
          save();
          render();
        }
      }),
  );
  $("#addproject").onclick = () => {
    let name = prompt("Nome do projeto:");
    if (!name?.trim()) return;
    let budget = prompt("Orçamento inicial (€):", "0");
    if (
      budget === null ||
      !Number.isFinite(Number(budget)) ||
      Number(budget) < 0
    )
      return;
    let id = crypto.randomUUID();
    db.projects.push({
      id,
      name: name.trim(),
      budget: Number(budget),
      members: [],
    });
    project = id;
    save();
    render();
  };
}
render();
