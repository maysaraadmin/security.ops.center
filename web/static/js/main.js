/**
 * EDR Agent Web Interface - Main JavaScript
 * Handles UI interactions, WebSocket communication, and data visualization
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Handle sidebar toggle
    const sidebarToggle = document.getElementById('sidebar-toggle');
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', function() {
            document.body.classList.toggle('sidebar-toggled');
            document.getElementById('sidebar').classList.toggle('toggled');
            
            // Store sidebar state in localStorage
            const isSidebarToggled = document.body.classList.contains('sidebar-toggled');
            localStorage.setItem('sidebarToggled', isSidebarToggled);
        });
        
        // Restore sidebar state from localStorage
        if (localStorage.getItem('sidebarToggled') === 'true') {
            document.body.classList.add('sidebar-toggled');
            document.getElementById('sidebar').classList.add('toggled');
        }
    }

    // Handle dropdown menus
    const dropdownElementList = [].slice.call(document.querySelectorAll('.dropdown-toggle'));
    dropdownElementList.map(function (dropdownToggleEl) {
        return new bootstrap.Dropdown(dropdownToggleEl);
    });

    // Handle active nav items
    const currentPath = window.location.pathname;
    document.querySelectorAll('.nav-link').forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
            // Also make sure parent dropdown is expanded
            const parentCollapse = link.closest('.collapse');
            if (parentCollapse) {
                parentCollapse.classList.add('show');
            }
        }
    });

    // Initialize charts if they exist on the page
    if (document.getElementById('metricsChart')) {
        initMetricsChart();
    }
    
    if (document.getElementById('threatChart')) {
        initThreatChart();
    }

    // Handle form submissions with fetch
    document.querySelectorAll('form[data-ajax="true"]').forEach(form => {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const submitBtn = this.querySelector('button[type="submit"]');
            const originalBtnText = submitBtn ? submitBtn.innerHTML : '';
            
            // Show loading state
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';
            }
            
            fetch(this.action, {
                method: this.method,
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => response.json())
            .then(data => {
                // Handle success response
                if (data.redirect) {
                    window.location.href = data.redirect;
                } else if (data.message) {
                    showAlert('success', data.message);
                }
                
                // Trigger custom event for other scripts to listen to
                const event = new CustomEvent('formSuccess', { detail: { form: this, data: data } });
                document.dispatchEvent(event);
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert('danger', 'An error occurred. Please try again.');
            })
            .finally(() => {
                // Restore button state
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalBtnText;
                }
            });
        });
    });

    // Initialize data tables if DataTables is included
    if (window.$.fn.DataTable) {
        $('.datatable').DataTable({
            responsive: true,
            pageLength: 25,
            order: [[0, 'desc']],
            dom: "<'row'<'col-sm-12 col-md-6'l><'col-sm-12 col-md-6'f>>" +
                 "<'row'<'col-sm-12'tr>>" +
                 "<'row'<'col-sm-12 col-md-5'i><'col-sm-12 col-md-7'p>>"
        });
    }
});

/**
 * Show a Bootstrap alert message
 * @param {string} type - Alert type (success, danger, warning, info)
 * @param {string} message - The message to display
 * @param {number} timeout - Time in ms to auto-dismiss (0 = don't auto-dismiss)
 */
function showAlert(type, message, timeout = 5000) {
    const alertHtml = `
        <div class="alert alert-${type} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    `;
    
    // Create a container for alerts if it doesn't exist
    let alertContainer = document.getElementById('alert-container');
    if (!alertContainer) {
        alertContainer = document.createElement('div');
        alertContainer.id = 'alert-container';
        alertContainer.style.position = 'fixed';
        alertContainer.style.top = '20px';
        alertContainer.style.right = '20px';
        alertContainer.style.zIndex = '9999';
        alertContainer.style.width = '350px';
        document.body.appendChild(alertContainer);
    }
    
    // Add the alert
    const alertElement = document.createElement('div');
    alertElement.innerHTML = alertHtml;
    alertContainer.appendChild(alertElement);
    
    // Auto-dismiss after timeout
    if (timeout > 0) {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alertElement.querySelector('.alert'));
            bsAlert.close();
        }, timeout);
    }
    
    // Handle alert close
    const closeButton = alertElement.querySelector('.btn-close');
    if (closeButton) {
        closeButton.addEventListener('click', () => {
            alertElement.remove();
        });
    }
}

/**
 * Format bytes to human-readable format
 * @param {number} bytes - Size in bytes
 * @param {number} decimals - Number of decimal places
 * @returns {string} Formatted string
 */
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/**
 * Format date to relative time (e.g., "2 minutes ago")
 * @param {string} dateString - ISO date string
 * @returns {string} Relative time string
 */
function timeAgo(dateString) {
    const date = new Date(dateString);
    const seconds = Math.floor((new Date() - date) / 1000);
    
    let interval = Math.floor(seconds / 31536000);
    if (interval >= 1) return interval + ' year' + (interval === 1 ? '' : 's') + ' ago';
    
    interval = Math.floor(seconds / 2592000);
    if (interval >= 1) return interval + ' month' + (interval === 1 ? '' : 's') + ' ago';
    
    interval = Math.floor(seconds / 86400);
    if (interval >= 1) return interval + ' day' + (interval === 1 ? '' : 's') + ' ago';
    
    interval = Math.floor(seconds / 3600);
    if (interval >= 1) return interval + ' hour' + (interval === 1 ? '' : 's') + ' ago';
    
    interval = Math.floor(seconds / 60);
    if (interval >= 1) return interval + ' minute' + (interval === 1 ? '' : 's') + ' ago';
    
    return Math.floor(seconds) + ' second' + (seconds === 1 ? '' : 's') + ' ago';
}

// Export functions to global scope if using modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        showAlert,
        formatBytes,
        timeAgo
    };
}
