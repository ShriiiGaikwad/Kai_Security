async function scanRepo() {
    const repo = document.getElementById('repoUrl').value.trim();
    const files = document.getElementById('repoFiles').value.trim().split(',').map(f => f.trim());

    if (!repo || files.length === 0) {
        alert("Please enter a valid GitHub repo URL and at least one file.");
        return;
    }

    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ repo, files })
        });

        const result = await response.json();
        document.getElementById('scanResult').innerText = response.ok ?
            "Scan completed successfully." : `Error: ${result.error}`;
    } catch (error) {
        console.error("Error calling /scan:", error);
        document.getElementById('scanResult').innerText = "An error occurred while scanning.";
    }
}

async function queryDatabase() {
    const severity = document.getElementById('querySeverity').value.trim();

    if (!severity) {
        alert("Please enter a severity level.");
        return;
    }

    try {
        const response = await fetch('/query', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filters: { severity } })
        });

        const result = await response.json();

        if (response.ok) {
            document.getElementById('queryResult').innerText = JSON.stringify(result, null, 2);
        } else {
            document.getElementById('queryResult').innerText = `Error: ${result.error}`;
        }
    } catch (error) {
        console.error("Error calling /query:", error);
        document.getElementById('queryResult').innerText = "An error occurred while querying.";
    }
}
