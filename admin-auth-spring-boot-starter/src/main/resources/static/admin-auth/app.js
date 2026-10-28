(function () {
    'use strict';

    var prefix = window.AA_PREFIX || '/admin-auth';
    var CSRF_COOKIE = 'XSRF-TOKEN';
    // 文案由服务端按请求语言注入（模板里的 window.AA_I18N），此处只做 {0} 占位符替换
    var I18N = window.AA_I18N || {};

    function t(key, value) {
        var pattern = I18N[key];
        if (typeof pattern !== 'string') {
            return key;
        }
        if (value === undefined || value === null) {
            return pattern;
        }
        return pattern.replace('{0}', String(value));
    }

    function readCookie(name) {
        var parts = document.cookie ? document.cookie.split('; ') : [];
        for (var i = 0; i < parts.length; i++) {
            var index = parts[i].indexOf('=');
            if (index > 0 && parts[i].substring(0, index) === name) {
                return decodeURIComponent(parts[i].substring(index + 1));
            }
        }
        return '';
    }

    async function ensureCsrf() {
        var token = readCookie(CSRF_COOKIE);
        if (!token) {
            await fetch(prefix + '/api/csrf', {
                method: 'GET',
                credentials: 'same-origin',
                headers: { 'Accept': 'application/json' }
            });
            token = readCookie(CSRF_COOKIE);
        }
        return token;
    }

    async function api(path, options) {
        var opts = options || {};
        var headers = Object.assign({ 'Accept': 'application/json' }, opts.headers || {});
        if (opts.body !== undefined && opts.body !== null) {
            headers['Content-Type'] = 'application/json';
        }
        if (opts.method && opts.method !== 'GET') {
            headers['X-XSRF-TOKEN'] = await ensureCsrf();
        }
        var response = await fetch(prefix + path, {
            method: opts.method || 'GET',
            headers: headers,
            body: opts.body === undefined || opts.body === null ? undefined : JSON.stringify(opts.body),
            credentials: 'same-origin'
        });
        var text = await response.text();
        var data = null;
        try {
            data = text ? JSON.parse(text) : null;
        } catch (ignored) {
            data = null;
        }
        if (!response.ok) {
            var error = new Error((data && data.message) || t('js.requestFailed', response.status));
            error.code = data && data.code;
            error.status = response.status;
            throw error;
        }
        return data;
    }

    function message(id, text, kind) {
        var element = document.getElementById(id || 'aa-message');
        if (!element) {
            return;
        }
        element.textContent = text || '';
        element.className = 'aa-message' + (kind ? ' aa-' + kind : '');
    }

    function ticket() {
        return sessionStorage.getItem('aa.ticket') || '';
    }

    function setTicket(value) {
        if (value) {
            sessionStorage.setItem('aa.ticket', value);
        } else {
            sessionStorage.removeItem('aa.ticket');
        }
    }

    // 只允许同源绝对路径：拒绝 //evil.com、/\evil.com 与带协议的 URL
    function isSafeRedirect(target) {
        if (!target || target.charAt(0) !== '/') {
            return false;
        }
        if (target.charAt(1) === '/' || target.charAt(1) === '\\') {
            return false;
        }
        try {
            var resolved = new URL(target, window.location.origin);
            return resolved.origin === window.location.origin;
        } catch (ignored) {
            return false;
        }
    }

    function rememberRedirect() {
        var target = new URLSearchParams(window.location.search).get('redirect');
        if (isSafeRedirect(target)) {
            sessionStorage.setItem('aa.redirect', target);
        }
    }

    function redirectAfterLogin() {
        var target = sessionStorage.getItem('aa.redirect') || '/';
        sessionStorage.removeItem('aa.redirect');
        window.location.href = isSafeRedirect(target) ? target : '/';
    }

    function handleNext(data) {
        setTicket(data.ticket || '');
        if (data.next === 'OK') {
            redirectAfterLogin();
        } else if (data.next === 'CHANGE_PASSWORD') {
            window.location.href = prefix + '/password-change';
        } else if (data.next === 'BIND_TOTP') {
            window.location.href = prefix + '/totp-setup';
        } else if (data.next === 'SELECT_FACTOR') {
            sessionStorage.setItem('aa.factors', JSON.stringify(data.factors || []));
            window.location.href = prefix + '/2fa';
        } else {
            message('aa-message', t('js.unknownNext', data.next), 'error');
        }
    }

    function toLogin() {
        window.location.href = prefix + '/login';
    }

    async function loginPage() {
        var form = document.getElementById('aa-login-form');
        form.addEventListener('submit', async function (event) {
            event.preventDefault();
            var button = form.querySelector('button[type="submit"]');
            button.disabled = true;
            message('aa-message', '');
            try {
                var data = await api('/api/login', {
                    method: 'POST',
                    body: {
                        identityType: document.getElementById('aa-identity-type').value,
                        identifier: document.getElementById('aa-identifier').value.trim(),
                        password: document.getElementById('aa-password').value
                    }
                });
                rememberRedirect();
                handleNext(data);
            } catch (error) {
                message('aa-message', error.message, 'error');
            } finally {
                button.disabled = false;
            }
        });
    }

    async function twoFactorPage() {
        if (!ticket()) {
            toLogin();
            return;
        }
        var factors = [];
        try {
            factors = JSON.parse(sessionStorage.getItem('aa.factors') || '[]');
        } catch (ignored) {
            factors = [];
        }
        var factor = factors.length ? factors[0] : 'TOTP';
        document.getElementById('aa-factor-label').textContent =
            factor === 'TOTP' ? t('js.factorTotp') : factor;

        var form = document.getElementById('aa-2fa-form');
        form.addEventListener('submit', async function (event) {
            event.preventDefault();
            message('aa-message', '');
            try {
                var data = await api('/api/mfa/verify', {
                    method: 'POST',
                    body: {
                        ticket: ticket(),
                        factorType: factor,
                        code: document.getElementById('aa-code').value.trim()
                    }
                });
                setTicket('');
                handleNext(data);
            } catch (error) {
                message('aa-message', error.message, 'error');
            }
        });

        var recoveryForm = document.getElementById('aa-recovery-form');
        document.getElementById('aa-use-recovery').addEventListener('click', function () {
            recoveryForm.classList.toggle('aa-hidden');
        });
        recoveryForm.addEventListener('submit', async function (event) {
            event.preventDefault();
            message('aa-recovery-message', '');
            try {
                var data = await api('/api/mfa/recovery', {
                    method: 'POST',
                    body: { ticket: ticket(), code: document.getElementById('aa-recovery-code').value.trim() }
                });
                setTicket('');
                handleNext(data);
            } catch (error) {
                message('aa-recovery-message', error.message, 'error');
            }
        });

        document.getElementById('aa-back-login').addEventListener('click', function (event) {
            event.preventDefault();
            setTicket('');
            toLogin();
        });
    }

    async function totpSetupPage() {
        var currentTicket = ticket();
        var init;
        try {
            init = await api('/api/mfa/totp/setup/init', {
                method: 'POST',
                body: { ticket: currentTicket || null }
            });
        } catch (error) {
            message('aa-message', error.message, 'error');
            if (error.status === 401) {
                setTicket('');
                setTimeout(toLogin, 800);
            }
            return;
        }

        document.getElementById('aa-qr').innerHTML = init.qrSvg;
        document.getElementById('aa-secret').textContent = init.manualSecret;
        document.getElementById('aa-copy-secret').addEventListener('click', function () {
            navigator.clipboard && navigator.clipboard.writeText(init.manualSecret);
        });

        var form = document.getElementById('aa-confirm-form');
        form.addEventListener('submit', async function (event) {
            event.preventDefault();
            message('aa-message', '');
            try {
                var data = await api('/api/mfa/totp/setup/confirm', {
                    method: 'POST',
                    body: { ticket: currentTicket || null, code: document.getElementById('aa-code').value.trim() }
                });
                sessionStorage.setItem('aa.recovery', JSON.stringify(data.recoveryCodes || []));
                setTicket('');
                window.location.href = prefix + '/recovery-codes';
            } catch (error) {
                message('aa-message', error.message, 'error');
            }
        });
    }

    async function passwordChangePage() {
        var initial = !!ticket();
        if (!initial) {
            try {
                await api('/api/me');
            } catch (ignored) {
                toLogin();
                return;
            }
        }
        document.getElementById('aa-hint').textContent = initial
            ? t('js.hintInitial')
            : t('js.hintNormal');

        var form = document.getElementById('aa-password-form');
        form.addEventListener('submit', async function (event) {
            event.preventDefault();
            message('aa-message', '');
            var oldPassword = document.getElementById('aa-old-password').value;
            var newPassword = document.getElementById('aa-new-password').value;
            var confirmPassword = document.getElementById('aa-confirm-password').value;
            if (newPassword !== confirmPassword) {
                message('aa-message', t('js.passwordMismatch'), 'error');
                return;
            }
            try {
                if (initial) {
                    var data = await api('/api/password/change-initial', {
                        method: 'POST',
                        body: { ticket: ticket(), oldPassword: oldPassword, newPassword: newPassword }
                    });
                    setTicket('');
                    handleNext(data);
                } else {
                    await api('/api/password/change', {
                        method: 'POST',
                        body: { oldPassword: oldPassword, newPassword: newPassword }
                    });
                    message('aa-message', t('js.passwordChanged'), 'ok');
                    setTimeout(toLogin, 900);
                }
            } catch (error) {
                message('aa-message', error.message, 'error');
            }
        });

        document.getElementById('aa-back-login').addEventListener('click', function (event) {
            event.preventDefault();
            toLogin();
        });
    }

    function recoveryCodesPage() {
        var codes = [];
        try {
            codes = JSON.parse(sessionStorage.getItem('aa.recovery') || '[]');
        } catch (ignored) {
            codes = [];
        }
        var list = document.getElementById('aa-codes');
        if (!codes.length) {
            message('aa-message', t('js.noRecoveryCodes'), 'error');
        }
        codes.forEach(function (code) {
            var item = document.createElement('li');
            item.textContent = code;
            list.appendChild(item);
        });

        document.getElementById('aa-copy-codes').addEventListener('click', function () {
            navigator.clipboard && navigator.clipboard.writeText(codes.join('\n'));
        });
        document.getElementById('aa-continue').addEventListener('click', function () {
            sessionStorage.removeItem('aa.recovery');
            redirectAfterLogin();
        });
    }

    window.AA = {
        loginPage: loginPage,
        twoFactorPage: twoFactorPage,
        totpSetupPage: totpSetupPage,
        passwordChangePage: passwordChangePage,
        recoveryCodesPage: recoveryCodesPage
    };
})();
