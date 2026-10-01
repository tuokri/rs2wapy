// @ts-check
"use strict";

/**
 * Disable a checked generator while its corresponding manual field has a value.
 *
 * @param {HTMLInputElement} input Manual player ID or player-name input.
 * @returns {void}
 */
function syncGenerationControl(input) {
    const controlName = input.dataset.generationInput;
    const control = document.querySelector(`[data-generation-control="${controlName}"]`);
    if (!(control instanceof HTMLLabelElement)) {
        return;
    }

    const checkbox = control.querySelector("input[type=checkbox]");
    const note = control.querySelector(".generation-override");
    if (!(checkbox instanceof HTMLInputElement) || !(note instanceof HTMLElement)) {
        return;
    }

    const hasManualValue = input.value.trim().length > 0;
    checkbox.disabled = hasManualValue;
    control.classList.toggle("is-overridden", hasManualValue);
    note.hidden = !hasManualValue;
}

for (const input of document.querySelectorAll("[data-generation-input]")) {
    if (!(input instanceof HTMLInputElement)) {
        continue;
    }
    input.addEventListener("input", () => syncGenerationControl(input));
    syncGenerationControl(input);
}
