// Глобальные переменные
let availableNodes = [];
let availableDocs = [];
let deleteTarget = { id: null, type: null }; // Для хранения цели удаления
let currentUser = null;
let activeViewerUrl = null;

const TOKEN_KEY = 'access_token';

const fileKindLabels = {
    image: 'Изображение',
    pdf: 'PDF',
    text: 'Текст',
    audio: 'Аудио',
    video: 'Видео',
    document: 'Документ',
    spreadsheet: 'Таблица',
    presentation: 'Презентация',
    archive: 'Архив',
    unknown: 'Файл'
};

function normalizeTitle(fileName, title) {
    const extensionMatch = fileName.match(/\.[^/.]+$/);
    const extension = extensionMatch ? extensionMatch[0].toLowerCase() : '';
    const trimmed = (title || '').trim();
    if (!trimmed) {
        return fileName.replace(/\.[^/.]+$/, '');
    }
    if (extension && trimmed.toLowerCase().endsWith(extension)) {
        return trimmed.slice(0, -extension.length).trim();
    }
    return trimmed;
}

function setAccessToken(token) {
    if (token) {
        localStorage.setItem(TOKEN_KEY, token);
    } else {
        localStorage.removeItem(TOKEN_KEY);
    }
}

function getAccessToken() {
    return localStorage.getItem(TOKEN_KEY);
}

async function refreshAccessToken() {
    const res = await fetch('/api/auth/refresh', { method: 'POST', credentials: 'include' });
    if (!res.ok) {
        setAccessToken(null);
        return false;
    }
    const data = await res.json();
    setAccessToken(data.access_token);
    return true;
}

async function apiFetch(url, options = {}) {
    const config = { credentials: 'include', ...options };
    const headers = new Headers(config.headers || {});
    const token = getAccessToken();
    if (token) {
        headers.set('Authorization', `Bearer ${token}`);
    }
    if (config.body && !(config.body instanceof FormData) && !headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json');
    }
    config.headers = headers;

    let res = await fetch(url, config);
    if (res.status === 401 && !config._retry) {
        const refreshed = await refreshAccessToken();
        if (refreshed) {
            config._retry = true;
            const retryHeaders = new Headers(config.headers || {});
            retryHeaders.set('Authorization', `Bearer ${getAccessToken()}`);
            config.headers = retryHeaders;
            res = await fetch(url, config);
        }
    }
    return res;
}

function setAuthMessage(elementId, message, type = 'danger') {
    const container = document.getElementById(elementId);
    if (!container) return;
    if (!message) {
        container.innerHTML = '';
        return;
    }
    container.innerHTML = `<div class="alert alert-${type}" role="alert">${message}</div>`;
}

function formatApiError(errorPayload) {
    if (!errorPayload) return 'Ошибка запроса';
    if (typeof errorPayload.detail === 'string') {
        return errorPayload.detail;
    }
    if (Array.isArray(errorPayload.detail)) {
        return errorPayload.detail
            .map((item) => item.msg || item.message || 'Ошибка валидации')
            .join(', ');
    }
    return 'Ошибка запроса';
}

function setAuthState(user) {
    currentUser = user;
    const isAuthenticated = Boolean(user);
    const sidebarLinks = document.querySelectorAll('.sidebar a');
    sidebarLinks.forEach(link => {
        if (link.dataset.section) {
            link.classList.toggle('disabled', !isAuthenticated);
        }
    });

    if (!isAuthenticated) {
        document.querySelectorAll('.section').forEach(el => el.classList.remove('active'));
        document.getElementById('auth').classList.add('active');
        sidebarLinks.forEach(link => link.classList.remove('active'));
        return;
    }

    document.getElementById('accountUsername').textContent = user.username;
    showSection('storage');
}

async function initAuth() {
    const token = getAccessToken();
    if (!token) {
        setAuthState(null);
        return;
    }
    const res = await apiFetch('/api/auth/me');
    if (res.ok) {
        const data = await res.json();
        setAuthState(data);
    } else {
        setAuthState(null);
    }
}

// --- Логика навигации ---
function showSection(id, event) {
    if (!currentUser && id !== 'auth') {
        setAuthState(null);
        return;
    }
    document.querySelectorAll('.section').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.sidebar a').forEach(el => el.classList.remove('active'));
    document.getElementById(id).classList.add('active');
    if (event?.target) {
        event.target.closest('a').classList.add('active');
    } else {
        const link = document.querySelector(`.sidebar a[data-section="${id}"]`);
        if (link) link.classList.add('active');
    }

    if (id === 'storage') loadNodes();
    if (id === 'data') loadDocs();
}

async function handleLogin(event) {
    event.preventDefault();
    setAuthMessage('authMessage', '');
    const formData = new FormData(event.target);
    const payload = Object.fromEntries(formData.entries());
    const res = await apiFetch('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify(payload)
    });
    if (!res.ok) {
        const err = await res.json();
        setAuthMessage('authMessage', formatApiError(err) || 'Ошибка входа');
        return;
    }
    const data = await res.json();
    setAccessToken(data.access_token);
    setAuthState(data.user);
    event.target.reset();
    loadNodes();
}

async function handleRegister(event) {
    event.preventDefault();
    setAuthMessage('authMessage', '');
    const formData = new FormData(event.target);
    const payload = Object.fromEntries(formData.entries());
    const res = await apiFetch('/api/auth/register', {
        method: 'POST',
        body: JSON.stringify(payload)
    });
    if (!res.ok) {
        const err = await res.json();
        setAuthMessage('authMessage', formatApiError(err) || 'Ошибка регистрации');
        return;
    }
    const data = await res.json();
    setAccessToken(data.access_token);
    setAuthState(data.user);
    event.target.reset();
    loadNodes();
}

async function handleLogout() {
    await apiFetch('/api/auth/logout', { method: 'POST' });
    setAccessToken(null);
    setAuthState(null);
}

async function handleChangePassword(event) {
    event.preventDefault();
    setAuthMessage('passwordMessage', '');
    const formData = new FormData(event.target);
    const payload = Object.fromEntries(formData.entries());
    const res = await apiFetch('/api/auth/change-password', {
        method: 'POST',
        body: JSON.stringify(payload)
    });
    if (!res.ok) {
        const err = await res.json();
        setAuthMessage('passwordMessage', formatApiError(err) || 'Не удалось обновить пароль');
        return;
    }
    setAuthMessage('passwordMessage', 'Пароль успешно обновлён', 'success');
    event.target.reset();
}

// --- Логика Хранилищ ---
async function loadNodes() {
    try {
        const res = await apiFetch('/api/nodes');
        if (!res.ok) {
            throw new Error('Не удалось загрузить узлы');
        }
        availableNodes = await res.json();
        const tbody = document.getElementById('nodesTableBody');
        tbody.innerHTML = '';
        availableNodes.forEach(node => {
            let statusBadge = '<span class="badge bg-success">Active</span>';
            let retryBtn = '';

            if (!node.is_active) {
                statusBadge = '<span class="badge bg-danger">Inactive</span>';
                retryBtn = `<button class="btn btn-sm btn-outline-secondary ms-2" onclick="retryNode(${node.id}, this)" title="Retry Connection"><i class="fas fa-sync-alt"></i></button>`;
            }

            tbody.innerHTML += `
                <tr>
                    <td>${node.id}</td>
                    <td>${node.ip}:${node.port}</td>
                    <td>${node.bucket_name}</td>
                    <td class="d-flex align-items-center">${statusBadge} ${retryBtn}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-danger" onclick="initDelete(${node.id}, 'node')"><i class="fas fa-trash"></i></button>
                    </td>
                </tr>
            `;
        });
        updateNodeSelectors();
    } catch (e) { console.error(e); }
}

document.getElementById('addNodeForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = document.getElementById('addNodeBtn');
    const icon = btn.querySelector('i');

    btn.disabled = true;
    icon.className = 'fas fa-spinner spin-anim';

    const formData = new FormData(e.target);

    try {
        const res = await apiFetch('/api/nodes', { method: 'POST', body: formData });
        if (res.ok) {
            e.target.reset();
            loadNodes();
        } else {
            const err = await res.json();
            alert('Ошибка: ' + err.detail);
        }
    } catch (e) {
        alert('Ошибка сети');
    } finally {
        btn.disabled = false;
        icon.className = 'fas fa-plus';
    }
});

async function retryNode(id, btn) {
    const icon = btn.querySelector('i');
    icon.classList.add('spin-anim');
    btn.disabled = true;

    try {
        const res = await apiFetch(`/api/nodes/${id}/check`, { method: 'POST' });
        if (res.ok) { loadNodes(); }
        else {
            alert('Узел все еще недоступен');
            btn.disabled = false;
            icon.classList.remove('spin-anim');
        }
    } catch (e) {
        btn.disabled = false;
        icon.classList.remove('spin-anim');
    }
}

// --- Логика Удаления (Модальное окно) ---
function initDelete(id, type) {
    deleteTarget = { id, type };
    new bootstrap.Modal(document.getElementById('deleteConfirmModal')).show();
}

async function confirmDelete() {
    const { id, type } = deleteTarget;
    const modalEl = document.getElementById('deleteConfirmModal');
    const modal = bootstrap.Modal.getInstance(modalEl);

    try {
        const endpoint = type === 'node' ? `/api/nodes/${id}` : `/api/documents/${id}`;
        await apiFetch(endpoint, { method: 'DELETE' });

        modal.hide();
        if (type === 'node') loadNodes();
        else loadDocs();
    } catch (e) { alert(e); }
}

// --- Логика Документов ---

function formatFileKind(doc) {
    const kind = doc.file_kind || 'unknown';
    if (kind !== 'unknown') {
        return fileKindLabels[kind] || fileKindLabels.unknown;
    }
    if (doc.file_extension) {
        return doc.file_extension.toUpperCase();
    }
    return fileKindLabels.unknown;
}

function renderKindBadge(doc) {
    const kindLabel = formatFileKind(doc);
    return `<span class="badge bg-secondary file-kind-badge">${kindLabel}</span>`;
}

async function loadDocs() {
    const res = await apiFetch('/api/documents');
    if (!res.ok) {
        throw new Error('Не удалось загрузить документы');
    }
    availableDocs = await res.json();
    const tbody = document.getElementById('docsTableBody');
    tbody.innerHTML = '';
    availableDocs.forEach(doc => {
        const date = new Date(doc.last_modified).toLocaleString();
        tbody.innerHTML += `
            <tr class="doc-row" ondblclick="openViewer('${doc.id}')">
                <td class="doc-title" onclick="openViewer('${doc.id}')"><strong>${doc.title}</strong></td>
                <td>${renderKindBadge(doc)}</td>
                <td><span class="badge bg-info text-dark">v${doc.active_version}</span></td>
                <td>${(doc.size / 1024).toFixed(2)} KB</td>
                <td>${date}</td>
                <td>
                    <div class="doc-actions">
                        <button class="btn btn-sm btn-primary" onclick="downloadDoc('${doc.id}')" title="Скачать"><i class="fas fa-download"></i></button>
                        <button class="btn btn-sm btn-warning" onclick="openEditModal('${doc.id}')" title="Обновить"><i class="fas fa-edit"></i></button>
                        <button class="btn btn-sm btn-danger" onclick="initDelete('${doc.id}', 'doc')" title="Удалить"><i class="fas fa-trash"></i></button>
                    </div>
                </td>
            </tr>
        `;
    });
}

function updateNodeSelectors() {
    const render = (containerId) => {
        const container = document.getElementById(containerId);
        if (!container) return;
        container.innerHTML = '';

        const activeNodes = availableNodes.filter(n => n.is_active);

        if (activeNodes.length === 0) {
            container.innerHTML = '<div class="text-danger small">Нет активных узлов</div>';
            return;
        }

        activeNodes.forEach(node => {
            container.innerHTML += `
                <div class="form-check">
                    <input class="form-check-input node-check" type="checkbox" value="${node.id}" id="chk${containerId}${node.id}" checked>
                    <label class="form-check-label" for="chk${containerId}${node.id}">
                        ${node.ip}:${node.port}
                    </label>
                </div>
            `;
        });
    };
    render('nodeSelectContainer');
    updateMaxK();
}

function updateMaxK() {
    const count = document.querySelectorAll('#nodeSelectContainer .node-check:checked').length;
    const kInput = document.getElementById('kInput');
    kInput.max = count > 0 ? count : 1;
    if (parseInt(kInput.value) > count) kInput.value = count;
    if (parseInt(kInput.value) < 1) kInput.value = 1;
}

document.addEventListener('change', (e) => {
    if (e.target.classList.contains('node-check')) updateMaxK();
});

function changeK(delta) {
    const input = document.getElementById('kInput');
    let val = parseInt(input.value) + delta;
    const max = parseInt(input.max);
    if (val >= 1 && val <= max) input.value = val;
}

async function submitUpload() {
    const fileInput = document.getElementById('fileInput');
    const titleInput = document.getElementById('titleInput');
    if (fileInput.files.length > 0) {
        const fileName = fileInput.files[0].name;
        titleInput.value = normalizeTitle(fileName, titleInput.value);
        // Проверка на дубликат (Frontend)
        const exists = availableDocs.find(d => d.title === titleInput.value.trim());
        if (exists) {
            new bootstrap.Modal(document.getElementById('duplicateWarningModal')).show();
            return;
        }
    }

    const form = document.getElementById('uploadDocForm');
    const formData = new FormData(form);

    const selectedNodes = Array.from(document.querySelectorAll('#nodeSelectContainer .node-check:checked')).map(el => parseInt(el.value));
    if (selectedNodes.length === 0) { alert('Выберите узлы!'); return; }

    formData.append('nodes', JSON.stringify(selectedNodes));

    const btn = document.querySelector('#uploadModal .btn-primary');
    const originalText = btn.textContent;
    btn.disabled = true; btn.textContent = 'Загрузка...';

    try {
        const res = await apiFetch('/api/documents', { method: 'POST', body: formData });
        if (res.ok) {
            bootstrap.Modal.getInstance(document.getElementById('uploadModal')).hide();
            form.reset();
            loadDocs();
        } else {
            const err = await res.json();
            alert('Ошибка: ' + err.detail);
        }
    } catch (e) { alert(e); }

    btn.disabled = false; btn.textContent = originalText;
}

document.getElementById('fileInput').addEventListener('change', (event) => {
    const titleInput = document.getElementById('titleInput');
    const file = event.target.files[0];
    if (!file) return;
    if (!titleInput.value.trim()) {
        titleInput.value = normalizeTitle(file.name, '');
    }
});

async function downloadDoc(id) {
    const doc = availableDocs.find(item => item.id === id);
    const res = await apiFetch(`/api/documents/${id}/download`);
    if (!res.ok) {
        alert('Не удалось скачать файл');
        return;
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    const extension = doc?.file_extension ? `.${doc.file_extension}` : '';
    link.href = url;
    link.download = doc?.title ? `${doc.title}${extension}` : `document${extension}`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
}

function openEditModal(id) {
    document.getElementById('editDocId').value = id;
    new bootstrap.Modal(document.getElementById('editModal')).show();
}

async function submitEdit() {
    const id = document.getElementById('editDocId').value;
    const form = document.getElementById('editDocForm');
    const formData = new FormData(form);

    try {
        const res = await apiFetch(`/api/documents/${id}/update`, { method: 'POST', body: formData });
        if (res.ok) {
            bootstrap.Modal.getInstance(document.getElementById('editModal')).hide();
            form.reset();
            loadDocs();
        } else {
            const err = await res.json();
            alert('Ошибка обновления: ' + err.detail);
        }
    } catch (e) { alert(e); }
}

async function openViewer(docId) {
    const doc = availableDocs.find(item => item.id === docId);
    if (!doc) return;

    const modalEl = document.getElementById('viewerModal');
    const modal = new bootstrap.Modal(modalEl);

    const viewerContent = document.getElementById('viewerContent');
    const viewerTitle = document.getElementById('viewerTitle');
    const viewerMeta = document.getElementById('viewerMeta');
    const downloadBtn = document.getElementById('viewerDownloadBtn');

    viewerContent.innerHTML = '';
    viewerTitle.textContent = doc.title;
    viewerMeta.textContent = `${formatFileKind(doc)} • ${(doc.size / 1024).toFixed(2)} KB`;
    downloadBtn.onclick = () => downloadDoc(doc.id);

    const kind = doc.file_kind || 'unknown';
    try {
        if (activeViewerUrl) {
            URL.revokeObjectURL(activeViewerUrl);
            activeViewerUrl = null;
        }

        const viewUrl = `/api/documents/${doc.id}/view`;
        const res = await apiFetch(viewUrl);
        if (!res.ok) {
            viewerContent.innerHTML = '<div class="alert alert-warning">Не удалось загрузить содержимое файла.</div>';
        } else if (kind === 'text') {
            const text = await res.text();
            viewerContent.innerHTML = `<div class="viewer-text"></div>`;
            viewerContent.querySelector('.viewer-text').textContent = text;
        } else if (kind === 'document' || kind === 'spreadsheet' || kind === 'presentation') {
            viewerContent.innerHTML = '<div class="alert alert-info">Предпросмотр этого формата пока не поддерживается. Вы можете скачать файл.</div>';
        } else {
            const blob = await res.blob();
            activeViewerUrl = URL.createObjectURL(blob);
            if (kind === 'image') {
                viewerContent.innerHTML = `<img src="${activeViewerUrl}" alt="${doc.title}" />`;
            } else if (kind === 'pdf') {
                viewerContent.innerHTML = `<iframe src="${activeViewerUrl}"></iframe>`;
            } else if (kind === 'audio') {
                viewerContent.innerHTML = `<audio controls src="${activeViewerUrl}"></audio>`;
            } else if (kind === 'video') {
                viewerContent.innerHTML = `<video controls src="${activeViewerUrl}"></video>`;
            } else {
                viewerContent.innerHTML = '<div class="alert alert-secondary">Формат файла не распознан. Используйте скачивание.</div>';
            }
        }
    } catch (e) {
        viewerContent.innerHTML = '<div class="alert alert-warning">Не удалось загрузить содержимое файла.</div>';
    }

    modal.show();
}

document.getElementById('loginForm').addEventListener('submit', handleLogin);
document.getElementById('registerForm').addEventListener('submit', handleRegister);
document.getElementById('changePasswordForm').addEventListener('submit', handleChangePassword);
document.getElementById('logoutBtn').addEventListener('click', handleLogout);

initAuth();
