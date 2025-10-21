document.addEventListener('DOMContentLoaded', () => {
    const urlForm = document.getElementById('urlForm');
    const urlInput = document.getElementById('urlInput');
    const checkBtn = urlForm.querySelector('button');
    const spinner = document.getElementById('spinner');
    const resultDisplay = document.getElementById('resultDisplay');
    const counterElement = document.getElementById('counter');

    // Load scan count from localStorage
    let scanCount = parseInt(localStorage.getItem('scanCount') || '0', 10);
    counterElement.textContent = scanCount;

    // Function to update result display
    const showResult = (data) => {
        const isPhishing = data.result === 'Phishing URL';
        resultDisplay.className = 'show ' + (isPhishing ? 'result-danger' : 'result-safe');
        resultDisplay.innerHTML = `
            <div class="result-icon">${isPhishing ? '<i class="fas fa-exclamation-triangle"></i>' : '<i class="fas fa-shield-alt"></i>'}</div>
            <strong>${data.result} (${data.confidence}% confidence)</strong>
            <div class="result-url">${data.url}</div>
        `;
    };

    urlForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const url = urlInput.value.trim();
        if (!url) {
            alert('⚠️ Please enter a URL to scan.');
            return;
        }

        // Show spinner and disable button
        spinner.style.display = 'block';
        checkBtn.disabled = true;
        checkBtn.textContent = 'Analyzing...';

        try {
            const res = await fetch('/predict', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            const data = await res.json();

            // Update UI with result
            showResult(data);

            // Update scan count
            scanCount++;
            counterElement.textContent = scanCount;
            localStorage.setItem('scanCount', scanCount);

        } catch (err) {
            alert('Error connecting to server.');
        } finally {
            spinner.style.display = 'none';
            checkBtn.disabled = false;
            checkBtn.textContent = 'Analyze URL Security';
        }
    });
});
