// public/js/dialog.js — dynamic modal/dialog manager.

let root;

function ensureRoot() {
    if (!root) root = document.getElementById('dialog-root');
    return root;
}

export function openDialog({ title, body, actions = [], variant }) {
    const host = ensureRoot();
    if (!host) return null;

    const scrim = document.createElement('div');
    scrim.className = 'dialog-scrim';
    const dialog = document.createElement('div');
    dialog.className = 'dialog' + (variant ? ` dialog--${variant}` : '');
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    dialog.setAttribute('aria-labelledby', 'dialog-title');

    const header = document.createElement('div');
    header.className = 'dialog__header';
    header.innerHTML = `
        <h3 class="dialog__title" id="dialog-title">${title ?? ''}</h3>
        <button type="button" class="icon-btn" data-dialog-close aria-label="Close">
            <span class="icon">close</span>
        </button>
    `;

    const bodyEl = document.createElement('div');
    bodyEl.className = 'dialog__body';
    if (typeof body === 'string') bodyEl.innerHTML = body;
    else if (body instanceof Node) bodyEl.appendChild(body);

    const actionsEl = document.createElement('div');
    actionsEl.className = 'dialog__actions';

    dialog.appendChild(header);
    dialog.appendChild(bodyEl);
    if (actions.length > 0) dialog.appendChild(actionsEl);

    scrim.appendChild(dialog);
    host.appendChild(scrim);

    let closed = false;
    const close = (result) => {
        if (closed) return;
        closed = true;
        scrim.classList.add('is-closing');
        setTimeout(() => scrim.remove(), 180);
        api._resolveClose?.(result);
    };

    actions.forEach(action => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = `btn ${action.variant ? `btn--${action.variant}` : 'btn--text'}`;
        btn.textContent = action.label;
        btn.addEventListener('click', async () => {
            try {
                const result = await action.onClick?.({ close, bodyEl });
                if (action.closeOnClick !== false) close(result);
            } catch (err) {
                console.error('Dialog action error:', err);
            }
        });
        actionsEl.appendChild(btn);
    });

    header.querySelector('[data-dialog-close]').addEventListener('click', () => close(undefined));
    scrim.addEventListener('click', (e) => { if (e.target === scrim) close(undefined); });

    const onKey = (e) => { if (e.key === 'Escape') close(undefined); };
    document.addEventListener('keydown', onKey);
    // Cleanup keydown after close
    const origRemove = scrim.remove.bind(scrim);
    scrim.remove = () => { document.removeEventListener('keydown', onKey); origRemove(); };

    // Focus first focusable element inside the body, or the close button
    requestAnimationFrame(() => {
        const f = bodyEl.querySelector('input, textarea, select, button');
        (f ?? header.querySelector('[data-dialog-close]')).focus();
    });

    const closedPromise = new Promise(res => { api._resolveClose = res; });
    const api = { close, scrim, dialog, bodyEl, closedPromise };
    return api;
}

export function confirmDialog({ title, message, confirmLabel = 'Confirm', cancelLabel = 'Cancel', variant = 'danger' } = {}) {
    return new Promise(resolve => {
        const d = openDialog({
            title,
            body: `<p>${message}</p>`,
            variant,
            actions: [
                { label: cancelLabel, variant: 'text', onClick: () => resolve(false) },
                { label: confirmLabel, variant: variant === 'danger' ? 'danger' : 'filled', onClick: () => resolve(true) }
            ]
        });
        d?.closedPromise.then(() => resolve(false));
    });
}
