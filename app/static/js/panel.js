let availableNodes = [];
let availableDocs = [];
let deleteTarget = { id: null, type: null };
let currentUser = null;

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

function showError(message) {
    const messageEl = document.getElementById('errorModalMessage');
    if (messageEl) {
        messageEl.textContent = message || 'Произошла ошибка.';
    }

    const modalEl = document.getElementById('errorModal');
    if (modalEl) {
        new bootstrap.Modal(modalEl).show();
    } else {
        alert(message || 'Произошла ошибка.');
    }
}

async function getErrorMessage(res, fallbackMessage = 'Произошла ошибка.') {
    try {
        const data = await res.json();
        return data?.detail || fallbackMessage;
    } catch {
        return fallbackMessage;
    }
}

async function apiFetch(url, options = {}) {
    const response = await fetch(url, {
        credentials: 'same-origin',
        ...options
    });

    if (response.status === 401) {
        window.location.href = '/auth/login';
        throw new Error('Unauthorized');
    }

    if (response.status === 403) {
        const message = await getErrorMessage(response, 'Недостаточно прав');
        showError(message);
        throw new Error('Forbidden');
    }

    return response;
}

async function loadCurrentUser() {
    try {
        const resp = await fetch('/api/me', {
            credentials: 'same-origin'
        });

        const authUserWrap = document.getElementById('auth-user-wrap');
        const authUserName = document.getElementById('auth-user-name');
        const authUserRole = document.getElementById('auth-user-role');
        const loginLink = document.getElementById('login-link');

        if (resp.status === 401) {
            window.location.href = '/auth/login';
            return null;
        }

        if (!resp.ok) {
            throw new Error('Не удалось получить текущего пользователя');
        }

        currentUser = await resp.json();
        const roles = Array.isArray(currentUser.roles) ? currentUser.roles : [];
        const primaryRole = roles.length > 0 ? roles[0] : 'user';

        if (authUserName) {
            authUserName.textContent = `${currentUser.username || 'unknown'} (${primaryRole})`;
        }

        if (authUserRole) {
            authUserRole.textContent = '';
        }

        if (authUserWrap) authUserWrap.style.display = 'flex';
        if (loginLink) loginLink.style.display = 'none';

        return currentUser;
    } catch (e) {
        console.error(e);
        showError('Не удалось получить информацию о текущем пользователе.');
        return null;
    }
}

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

function showSection(id, event) {
    document.querySelectorAll('.section').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.sidebar a').forEach(el => el.classList.remove('active'));

    const section = document.getElementById(id);
    if (section) section.classList.add('active');

    if (event?.target) {
        const link = event.target.closest('a');
        if (link) link.classList.add('active');
    }

    if (id === 'storage') loadNodes();
    if (id === 'data') loadDocs();
}

// --- Логика Хранилищ ---
async function loadNodes() {
    try {
        const res = await apiFetch('/api/nodes');
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
    } catch (e) {
        if (e.message !== 'Forbidden' && e.message !== 'Unauthorized') {
            console.error(e);
            showError('Не удалось загрузить список узлов.');
        }
    }
}

async function loadUploadNodes() {
    try {
        const res = await apiFetch('/api/nodes');
        availableNodes = await res.json();
        updateNodeSelectors();
    } catch (e) {
        if (e.message !== 'Forbidden' && e.message !== 'Unauthorized') {
            showError('Не удалось загрузить список узлов для загрузки.');
        }
    }
}

document.getElementById('uploadModal')?.addEventListener('show.bs.modal', async () => {
    await loadUploadNodes();
});

document.getElementById('addNodeForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();

    const btn = document.getElementById('addNodeBtn');
    const icon = btn.querySelector('i');

    btn.disabled = true;
    icon.className = 'fas fa-spinner spin-anim';

    const formData = new FormData(e.target);

    try {
        const res = await apiFetch('/api/nodes', {
            method: 'POST',
            body: formData
        });

        if (res.ok) {
            e.target.reset();
            loadNodes();
        } else {
            const errMessage = await getErrorMessage(res, 'Ошибка при добавлении узла.');
            showError(errMessage);
        }
    } catch (e) {
        if (e.message !== 'Forbidden' && e.message !== 'Unauthorized') {
            showError('Ошибка сети');
        }
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

        if (res.ok) {
            loadNodes();
        } else {
            showError('Узел всё ещё недоступен');
            btn.disabled = false;
            icon.classList.remove('spin-anim');
        }
    } catch (e) {
        if (e.message !== 'Forbidden' && e.message !== 'Unauthorized') {
            btn.disabled = false;
            icon.classList.remove('spin-anim');
            showError('Не удалось проверить узел.');
        }
    }
}

// --- Логика Удаления ---
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
        const res = await apiFetch(endpoint, { method: 'DELETE' });

        if (!res.ok) {
            const errMessage = await getErrorMessage(res, 'Не удалось удалить объект.');
            showError(errMessage);
            return;
        }

        modal.hide();
        if (type === 'node') loadNodes();
        else loadDocs();
    } catch (e) {
        if (e.message !== 'Forbidden' && e.message !== 'Unauthorized') {
            console.error(e);
            showError('Не удалось удалить объект.');
        }
    }
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
    try {
        const res = await apiFetch('/api/documents');
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
    } catch (e) {
        if (e.message !== 'Forbidden' && e.message !== 'Unauthorized') {
            console.error(e);
            showError('Не удалось загрузить список документов.');
        }
    }
}

function updateNodeSelectors() {
    const container = document.getElementById('nodeSelectContainer');
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
                <input class="form-check-input node-check" type="checkbox" value="${node.id}" id="chknodeSelectContainer${node.id}" checked>
                <label class="form-check-label" for="chknodeSelectContainer${node.id}">
                    ${node.ip}:${node.port}
                </label>
            </div>
        `;
    });

    updateMaxK();
}

function updateMaxK() {
    const count = document.querySelectorAll('#nodeSelectContainer .node-check:checked').length;
    const kInput = document.getElementById('kInput');
    if (!kInput) return;

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
    if (!availableNodes.length) {
        await loadUploadNodes();
    }

    const fileInput = document.getElementById('fileInput');
    const titleInput = document.getElementById('titleInput');

    if (fileInput.files.length > 0) {
        const fileName = fileInput.files[0].name;
        titleInput.value = normalizeTitle(fileName, titleInput.value);

        const exists = availableDocs.find(d => d.title === titleInput.value.trim());
        if (exists) {
            new bootstrap.Modal(document.getElementById('duplicateWarningModal')).show();
            return;
        }
    }

    const form = document.getElementById('uploadDocForm');
    const formData = new FormData(form);

    const selectedNodes = Array.from(
        document.querySelectorAll('#nodeSelectContainer .node-check:checked')
    ).map(el => parseInt(el.value));

    if (selectedNodes.length === 0) {
        showError('Выберите узлы!');
        return;
    }

    formData.append('nodes', JSON.stringify(selectedNodes));

    const btn = document.querySelector('#uploadModal .btn-primary');
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Загрузка...';

    try {
        const res = await apiFetch('/api/documents', {
            method: 'POST',
            body: formData
        });

        if (res.ok) {
            bootstrap.Modal.getInstance(document.getElementById('uploadModal')).hide();
            form.reset();
            loadDocs();
        } else {
            const errMessage = await getErrorMessage(res, 'Ошибка загрузки.');
            showError(errMessage);
        }
    } catch (e) {
        if (e.message !== 'Forbidden' && e.message !== 'Unauthorized') {
            showError('Ошибка загрузки.');
        }
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

document.getElementById('fileInput')?.addEventListener('change', (event) => {
    const titleInput = document.getElementById('titleInput');
    const file = event.target.files[0];
    if (!file) return;
    if (!titleInput.value.trim()) {
        titleInput.value = normalizeTitle(file.name, '');
    }
});

async function downloadDoc(id) {
    try {
        const res = await apiFetch(`/api/documents/${id}/download`);

        if (!res.ok) {
            const message = await getErrorMessage(res, 'Не удалось скачать документ.');
            showError(message);
            return;
        }

        const blob = await res.blob();

        let filename = 'document.bin';
        const disposition = res.headers.get('Content-Disposition');
        if (disposition) {
            const match = disposition.match(/filename\*=UTF-8''([^;]+)/);
            if (match && match[1]) {
                filename = decodeURIComponent(match[1]);
            }
        }

        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);
    } catch (e) {
        if (e.message !== 'Forbidden' && e.message !== 'Unauthorized') {
            console.error(e);
            showError('Не удалось скачать документ.');
        }
    }
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
        const res = await apiFetch(`/api/documents/${id}/update`, {
            method: 'POST',
            body: formData
        });

        if (res.ok) {
            bootstrap.Modal.getInstance(document.getElementById('editModal')).hide();
            form.reset();
            loadDocs();
        } else {
            const errMessage = await getErrorMessage(res, 'Ошибка обновления.');
            showError(errMessage);
        }
    } catch (e) {
        if (e.message !== 'Forbidden' && e.message !== 'Unauthorized') {
            showError('Ошибка обновления.');
        }
    }
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
    const viewUrl = `/api/documents/${doc.id}/view`;

    try {
        const res = await apiFetch(viewUrl);

        if (!res.ok) {
            const message = await getErrorMessage(res, 'Не удалось открыть документ.');
            showError(message);
            return;
        }

        const blob = await res.blob();
        const blobUrl = URL.createObjectURL(blob);

        if (kind === 'image') {
            viewerContent.innerHTML = `<img src="${blobUrl}" alt="preview" class="img-fluid rounded">`;
        } else if (kind === 'pdf') {
            viewerContent.innerHTML = `<iframe src="${blobUrl}"></iframe>`;
        } else if (kind === 'audio') {
            viewerContent.innerHTML = `<audio controls class="w-100"><source src="${blobUrl}"></audio>`;
        } else if (kind === 'video') {
            viewerContent.innerHTML = `<video controls class="w-100"><source src="${blobUrl}"></video>`;
        } else if (kind === 'text') {
            const text = await blob.text();
            viewerContent.innerHTML = `<div class="viewer-text"></div>`;
            viewerContent.querySelector('.viewer-text').textContent = text;
        } else if (kind === 'document' || kind === 'spreadsheet' || kind === 'presentation') {
            viewerContent.innerHTML = `
                <div class="alert alert-secondary mb-0">
                    Предпросмотр этого формата пока не поддерживается. Вы можете скачать файл.
                </div>
            `;
        } else {
            viewerContent.innerHTML = `
                <div class="alert alert-secondary mb-0">
                    Формат файла не распознан. Используйте скачивание.
                </div>
            `;
        }

        modal.show();

        modalEl.addEventListener('hidden.bs.modal', () => {
            try {
                URL.revokeObjectURL(blobUrl);
            } catch (_) {}
        }, { once: true });

    } catch (e) {
        if (e.message !== 'Forbidden' && e.message !== 'Unauthorized') {
            console.error(e);
            showError('Не удалось открыть документ.');
        }
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    const user = await loadCurrentUser();
    if (!user) return;

    await loadDocs();
});