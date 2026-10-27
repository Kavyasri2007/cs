/**
 * Web Server Security Lab — Client JavaScript Helpers
 * Provides 1-click payload inserters and laboratory database reset triggers.
 */

document.addEventListener("DOMContentLoaded", function () {
    // Laboratory Database Reset Handler
    const resetBtn = document.getElementById("resetLabBtn");
    if (resetBtn) {
        resetBtn.addEventListener("click", function () {
            if (confirm("Reset the SQLite database back to original seeded accounts and statuses?")) {
                fetch("/api/reset-lab", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" }
                })
                .then(res => res.json())
                .then(data => {
                    alert(data.message || "Database successfully reset!");
                    window.location.reload();
                })
                .catch(err => {
                    alert("Error resetting database: " + err);
                });
            }
        });
    }
});

// Module 1: SQL Injection Payload Helper
function loadSqliPayload(prefix, username, password) {
    const userField = document.getElementById(prefix + "_username");
    const passField = document.getElementById(prefix + "_password");
    if (userField) userField.value = username;
    if (passField) passField.value = password;
}

// Module 2: OS Command Injection Payload Helper
function loadCmdPayload(prefix, target) {
    const targetField = document.getElementById(prefix + "_target");
    if (targetField) targetField.value = target;
}

// Module 3: Reflected XSS Payload Helper
function loadXssPayload(prefix, query) {
    const qField = document.getElementById(prefix + "_q");
    if (qField) qField.value = query;
}
