/*
 * Copyright (c) 2026 Tuomo Kriikkula
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

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
