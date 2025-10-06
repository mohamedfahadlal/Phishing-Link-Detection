document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('url-form');
    const checkBtn = document.getElementById('check-btn');
    const urlInput = document.getElementById('url-input');
    const loading = document.getElementById('loading');
    const result = document.getElementById('result');
    
    // Show loading animation when form is submitted
    form.addEventListener('submit', function(e) {
        // Validate URL format
        const url = urlInput.value.trim();
        if (!isValidUrl(url)) {
            e.preventDefault();
            alert('Please enter a valid URL (e.g., https://www.example.com)');
            return;
        }
        
        // Show loading animation
        if (loading) {
            loading.style.display = 'block';
        }
        
        // Hide previous result if exists
        if (result) {
            result.style.display = 'none';
        }
        
        // Disable button to prevent multiple submissions
        checkBtn.disabled = true;
        checkBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
    });
    
    // URL validation function
    function isValidUrl(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }
    
    // Re-enable button if page reloads (for back button cases)
    window.addEventListener('pageshow', function() {
        checkBtn.disabled = false;
        checkBtn.innerHTML = '<i class="fas fa-search"></i> Check URL';
        if (loading) {
            loading.style.display = 'none';
        }
    });
    
    // Hide loading if there's an existing result (page back navigation)
    if (result && result.textContent.trim() !== '') {
        if (loading) {
            loading.style.display = 'none';
        }
    }
});