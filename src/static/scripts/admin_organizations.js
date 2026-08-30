"use strict";
/* global jQuery, bootstrap, _post:readable, _delete:readable, BASE_URL:readable, reload:readable, jdenticon:readable */

function deleteOrganization(event) {
    event.preventDefault();
    event.stopPropagation();
    const org_uuid = event.target.dataset.vwOrgUuid;
    const org_name = event.target.dataset.vwOrgName;
    const billing_email = event.target.dataset.vwBillingEmail;
    if (!org_uuid) {
        alert("Required parameters not found!");
        return false;
    }

    // First make sure the user wants to delete this organization
    const continueDelete = confirm(`WARNING: All data of this organization (${org_name}) will be lost!\nMake sure you have a backup, this cannot be undone!`);
    if (continueDelete == true) {
        const input_org_uuid = prompt(`To delete the organization "${org_name} (${billing_email})", please type the organization uuid below.`);
        if (input_org_uuid != null) {
            if (input_org_uuid == org_uuid) {
                _post(`${BASE_URL}/admin/organizations/${org_uuid}/delete`,
                    "Organization deleted correctly",
                    "Error deleting organization"
                );
            } else {
                alert("Wrong organization uuid, please try again");
            }
        }
    }
}

// SCIM token management.
//
// The plaintext token exists only in the response to the call that generated it; the server stores
// a hash. It is shown once in the modal below and never persisted anywhere by this page.
function showScimModal(orgName, endpoint, token) {
    document.getElementById("scimModalOrgName").textContent = orgName;
    document.getElementById("scimEndpointValue").value = endpoint;

    const tokenBlock = document.getElementById("scimTokenBlock");
    const tokenValue = document.getElementById("scimTokenValue");
    if (token) {
        tokenValue.value = token;
        tokenBlock.classList.remove("d-none");
    } else {
        tokenValue.value = "";
        tokenBlock.classList.add("d-none");
    }

    const modalElement = document.getElementById("scimModal");
    // Once the operator closes the dialog the token is gone from the DOM too.
    modalElement.addEventListener("hidden.bs.modal", () => {
        tokenValue.value = "";
        reload();
    }, { once: true });

    bootstrap.Modal.getOrCreateInstance(modalElement).show();
}

async function rotateScimToken(event) {
    event.preventDefault();
    event.stopPropagation();

    const org_uuid = event.target.dataset.vwOrgUuid;
    const org_name = event.target.dataset.vwOrgName;
    const configured = event.target.dataset.vwScimConfigured === "true";
    if (!org_uuid) {
        alert("Required parameters not found!");
        return false;
    }

    if (configured) {
        const confirmed = confirm(`Generate a new SCIM token for "${org_name}"?\n\nThe current token stops working immediately and the identity provider has to be updated with the new one.`);
        if (!confirmed) {
            return false;
        }
    }

    try {
        const response = await fetch(`${BASE_URL}/admin/organizations/${org_uuid}/scim/token`, {
            method: "POST",
            mode: "same-origin",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" }
        });

        if (!response.ok) {
            const body = await response.text();
            let message = `${response.status} - ${response.statusText}`;
            try {
                const parsed = JSON.parse(body);
                if (parsed.errorModel && parsed.errorModel.message) {
                    message = parsed.errorModel.message;
                }
            } catch { /* keep the status line */ }
            alert(`Error generating SCIM token\n${message}`);
            return false;
        }

        const data = await response.json();
        showScimModal(org_name, data.endpoint, data.token);
    } catch (e) {
        alert(`Error generating SCIM token\n${e}`);
    }
    return true;
}

function revokeScimToken(event) {
    event.preventDefault();
    event.stopPropagation();

    const org_uuid = event.target.dataset.vwOrgUuid;
    const org_name = event.target.dataset.vwOrgName;
    if (!org_uuid) {
        alert("Required parameters not found!");
        return false;
    }

    const confirmed = confirm(`Revoke the SCIM token for "${org_name}"?\n\nProvisioning from the identity provider stops working immediately.`);
    if (confirmed) {
        _delete(`${BASE_URL}/admin/organizations/${org_uuid}/scim/token`,
            "SCIM token revoked",
            "Error revoking SCIM token"
        );
    }
    return true;
}

function showScimEndpoint(event) {
    event.preventDefault();
    event.stopPropagation();
    showScimModal(event.target.dataset.vwOrgName, event.target.dataset.vwScimEndpoint, null);
    return true;
}

async function copyFieldValue(event) {
    const target = document.getElementById(event.target.dataset.vwCopyTarget);
    if (!target) {
        return;
    }

    try {
        await navigator.clipboard.writeText(target.value);
        const original = event.target.textContent;
        event.target.textContent = "Copied";
        setTimeout(() => { event.target.textContent = original; }, 1500);
    } catch {
        // Clipboard access needs a secure context; selecting the text is the next best thing.
        target.select();
    }
}

function initActions() {
    document.querySelectorAll("button[vw-delete-organization]").forEach(btn => {
        btn.addEventListener("click", deleteOrganization);
    });
    document.querySelectorAll("button[vw-scim-rotate]").forEach(btn => {
        btn.addEventListener("click", rotateScimToken);
    });
    document.querySelectorAll("button[vw-scim-revoke]").forEach(btn => {
        btn.addEventListener("click", revokeScimToken);
    });
    document.querySelectorAll("button[vw-scim-endpoint]").forEach(btn => {
        btn.addEventListener("click", showScimEndpoint);
    });

    if (jdenticon) {
        jdenticon();
    }
}

// onLoad events
document.addEventListener("DOMContentLoaded", (/*event*/) => {
    jQuery("#orgs-table").DataTable({
        "drawCallback": function() {
            initActions();
        },
        "stateSave": true,
        "responsive": true,
        "lengthMenu": [
            [-1, 5, 10, 25, 50],
            ["All", 5, 10, 25, 50]
        ],
        "pageLength": -1, // Default show all
        "columnDefs": [{
            "targets": [4,5,6],
            "searchable": false,
            "orderable": false
        }]
    });

    // Add click events for organization actions
    initActions();

    document.querySelectorAll("button[data-vw-copy-target]").forEach(btn => {
        btn.addEventListener("click", copyFieldValue);
    });

    const btnReload = document.getElementById("reload");
    if (btnReload) {
        btnReload.addEventListener("click", reload);
    }
});
