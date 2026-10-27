/**
 * CampusConnect — Student Portal Client Scripts
 * Handles Demo Mode drawer toggling, 1-click payload loading, and mode switching.
 */

document.addEventListener("DOMContentLoaded", function () {
    const triggerBtn = document.getElementById("demoTriggerBtn");
    const drawer = document.getElementById("demoDrawer");
    const backdrop = document.getElementById("demoDrawerBackdrop");
    const closeBtn = document.getElementById("demoDrawerCloseBtn");

    if (triggerBtn && drawer && backdrop) {
        triggerBtn.addEventListener("click", function () {
            drawer.classList.add("open");
            backdrop.classList.add("open");
        });

        function closeDrawer() {
            drawer.classList.remove("open");
            backdrop.classList.remove("open");
        }

        if (closeBtn) closeBtn.addEventListener("click", closeDrawer);
        backdrop.addEventListener("click", closeDrawer);
    }
});

/**
 * Switches global Demo Mode between 'vulnerable' and 'secure'
 */
function switchDemoMode(mode) {
    fetch("/demo/set-mode", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest"
        },
        body: JSON.stringify({ mode: mode })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            window.location.reload();
        } else {
            alert("Error switching mode: " + (data.error || "Unknown error"));
        }
    })
    .catch(err => {
        alert("Failed to communicate with mode endpoint: " + err);
    });
}

/**
 * 1-Click Fillers for Presentation
 */
function fillLoginForm(user, pass) {
    const u = document.getElementById("username");
    const p = document.getElementById("password");
    if (u) u.value = user;
    if (p) p.value = pass;
    // Highlight input for presentation feedback
    if (u) {
        u.focus();
        u.style.borderColor = "#2563eb";
    }
}

function fillSearchForm(query) {
    const q = document.getElementById("search_query");
    if (q) {
        q.value = query;
        q.focus();
        q.style.borderColor = "#2563eb";
    }
}

function fillDiagnosticForm(target) {
    const t = document.getElementById("diagnostic_target");
    if (t) {
        t.value = target;
        t.focus();
        t.style.borderColor = "#2563eb";
    }
}

/**
 * Resets lab database back to pristine seeded student accounts
 */
function resetLabDatabase() {
    if (confirm("Reset SQLite database back to original seeded student accounts (Alice, Bob, Admin)?")) {
        fetch("/api/reset-lab", {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        })
        .then(res => res.json())
        .then(data => {
            alert(data.message || "Database reset successfully!");
            window.location.reload();
        })
        .catch(err => {
            alert("Reset error: " + err);
        });
    }
}
