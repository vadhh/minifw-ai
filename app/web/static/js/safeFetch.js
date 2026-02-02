/**
 * MiniFW-AI Global Fetch Utilities
 * Provides centralized error handling for all API calls
 */

/**
 * Safe fetch wrapper with automatic error handling
 * Handles 401, 403, 422, and 500 responses gracefully
 * 
 * @param {string} url - The URL to fetch
 * @param {object} options - Fetch options
 * @returns {Promise<Response>}
 */
async function safeFetch(url, options = {}) {
    try {
        const response = await fetch(url, options);

        // Handle 401 Unauthorized - redirect to login
        if (response.status === 401) {
            showGlobalAlert('Session expired. Redirecting to login...', 'warning');
            setTimeout(() => {
                window.location.href = '/auth/login?expired=1';
            }, 1500);
            throw new Error('Session expired');
        }

        // Handle 403 Forbidden
        if (response.status === 403) {
            showGlobalAlert('Access denied: insufficient permissions', 'danger');
            throw new Error('Forbidden');
        }

        // Handle 422 Validation Error
        if (response.status === 422) {
            const data = await response.json();
            let errorMessage = 'Validation error';
            if (data.detail) {
                if (Array.isArray(data.detail)) {
                    errorMessage = data.detail.map(e => e.msg || e.message || String(e)).join(', ');
                } else {
                    errorMessage = String(data.detail);
                }
            }
            showGlobalAlert(`Validation error: ${errorMessage}`, 'warning');
            throw new Error('Validation failed: ' + errorMessage);
        }

        // Handle 500 Server Error
        if (response.status === 500) {
            console.error('Server Error (500):', url);
            showGlobalAlert(
                'Server error occurred. Please try again or contact support if the problem persists.',
                'danger'
            );
            throw new Error('Server error');
        }

        // Handle other 5xx errors
        if (response.status >= 500) {
            console.error(`Server Error (${response.status}):`, url);
            showGlobalAlert('Service temporarily unavailable. Please try again later.', 'danger');
            throw new Error('Service unavailable');
        }

        return response;
    } catch (error) {
        // Handle network errors (fetch failed entirely)
        if (error.message === 'Failed to fetch') {
            showGlobalAlert('Network error. Please check your connection.', 'danger');
        }
        throw error;
    }
}

/**
 * Safe fetch wrapper that automatically parses JSON
 * @param {string} url - The URL to fetch
 * @param {object} options - Fetch options
 * @returns {Promise<any>} Parsed JSON response
 */
async function safeFetchJSON(url, options = {}) {
    const response = await safeFetch(url, options);
    return response.json();
}

/**
 * POST JSON data with automatic error handling
 * @param {string} url - The URL to POST to
 * @param {object} data - Data to send as JSON
 * @returns {Promise<any>} Parsed JSON response
 */
async function safePostJSON(url, data) {
    return safeFetchJSON(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
}

/**
 * PUT JSON data with automatic error handling
 * @param {string} url - The URL to PUT to
 * @param {object} data - Data to send as JSON
 * @returns {Promise<any>} Parsed JSON response
 */
async function safePutJSON(url, data) {
    return safeFetchJSON(url, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
}

/**
 * DELETE with automatic error handling
 * @param {string} url - The URL to DELETE
 * @returns {Promise<any>} Parsed JSON response
 */
async function safeDeleteJSON(url) {
    return safeFetchJSON(url, {
        method: 'DELETE'
    });
}

/**
 * Show a global alert notification
 * Uses SweetAlert2 Toast if available, falls back to Bootstrap alert
 * 
 * @param {string} message - Alert message
 * @param {string} type - Alert type: 'success', 'danger', 'warning', 'info'
 */
function showGlobalAlert(message, type = 'info') {
    // Map type to SweetAlert2 icon
    const iconMap = {
        'success': 'success',
        'danger': 'error',
        'warning': 'warning',
        'info': 'info'
    };

    // Try SweetAlert2 Toast first (if available)
    if (typeof Swal !== 'undefined') {
        const Toast = Swal.mixin({
            toast: true,
            position: 'top-end',
            showConfirmButton: false,
            timer: 5000,
            timerProgressBar: true,
            didOpen: (toast) => {
                toast.onmouseenter = Swal.stopTimer;
                toast.onmouseleave = Swal.resumeTimer;
            }
        });

        Toast.fire({
            icon: iconMap[type] || 'info',
            title: message
        });
        return;
    }

    // Fallback to Bootstrap alert
    let container = document.getElementById('alertContainer');
    if (!container) {
        // Create container if it doesn't exist
        container = document.createElement('div');
        container.id = 'alertContainer';
        container.style.cssText = 'position: fixed; top: 70px; right: 20px; z-index: 9999; max-width: 400px;';
        document.body.appendChild(container);
    }

    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.innerHTML = `
    <i class="bi bi-${type === 'danger' ? 'exclamation-triangle' : type === 'warning' ? 'exclamation-circle' : type === 'success' ? 'check-circle' : 'info-circle'}"></i>
    ${escapeHtmlGlobal(message)}
    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
  `;

    container.appendChild(alert);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (alert.parentNode) {
            alert.remove();
        }
    }, 5000);
}

/**
 * Escape HTML to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} Escaped HTML
 */
function escapeHtmlGlobal(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Export for module usage (if needed)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { safeFetch, safeFetchJSON, safePostJSON, safePutJSON, safeDeleteJSON, showGlobalAlert };
}
