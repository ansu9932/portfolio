/* =====================================================================
 * contact.js — handles the contact form submission for contact.html
 * - fetches a signed anti-bot token on load
 * - submits via fetch (AJAX) to contact.php
 * - shows inline success / error feedback using the template's .form__reply
 * ===================================================================== */
(function () {
  "use strict";

  var form = document.getElementById("contact-form");
  if (!form) return;

  var ENDPOINT   = "contact.php";
  var tokenField = document.getElementById("cf-token");
  var submitBtn  = document.getElementById("cf-submit");
  var formWrap   = form; // has .form (fades via .is-hidden)
  var reply      = document.getElementById("cf-reply");
  var replyTitle = document.getElementById("cf-reply-title");
  var replyText  = document.getElementById("cf-reply-text");
  var replyBox   = reply;

  // ---- fetch a fresh token --------------------------------------------
  function refreshToken() {
    return fetch(ENDPOINT + "?action=token", {
      headers: { "X-Requested-With": "XMLHttpRequest" },
      cache: "no-store"
    })
      .then(function (r) { return r.json(); })
      .then(function (d) { if (d && d.token && tokenField) tokenField.value = d.token; })
      .catch(function () { /* leave empty; server will reject and ask to reload */ });
  }
  refreshToken();

  // ---- helpers ---------------------------------------------------------
  function clearErrors() {
    form.querySelectorAll(".has-error").forEach(function (el) {
      el.classList.remove("has-error");
    });
  }

  function markErrors(errors) {
    if (!errors) return;
    Object.keys(errors).forEach(function (key) {
      var field = form.querySelector('[name="' + key + '"]');
      if (field) field.classList.add("has-error");
    });
  }

  function showReply(message, isError) {
    replyText.textContent = message;
    replyTitle.textContent = isError ? "Oops!" : "Thank you!";
    replyBox.classList.toggle("is-error", !!isError);
    if (isError) {
      // keep form visible for errors, just surface the message above the button
      replyBox.classList.add("is-visible");
      setTimeout(function () { replyBox.classList.remove("is-visible"); }, 6000);
    } else {
      formWrap.classList.add("is-hidden");
      replyBox.classList.add("is-visible");
    }
  }

  function setBusy(busy) {
    if (!submitBtn) return;
    submitBtn.disabled = busy;
    submitBtn.classList.toggle("is-busy", busy);
  }

  // ---- submit ----------------------------------------------------------
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    clearErrors();

    // lightweight client-side check (server is the source of truth)
    if (!form.checkValidity()) {
      var firstInvalid = form.querySelector(":invalid");
      if (firstInvalid) {
        firstInvalid.classList.add("has-error");
        firstInvalid.focus();
      }
      showReply("Please fill in the required fields correctly.", true);
      return;
    }

    setBusy(true);

    var data = new FormData(form);

    fetch(ENDPOINT, {
      method: "POST",
      headers: { "X-Requested-With": "XMLHttpRequest" },
      body: data
    })
      .then(function (r) {
        return r.json().then(function (json) { return { status: r.status, json: json }; });
      })
      .then(function (res) {
        var d = res.json || {};
        if (res.status === 200 && d.ok) {
          form.reset();
          showReply(d.message || "Your message has been sent.", false);
        } else {
          markErrors(d.errors);
          showReply(d.message || "Something went wrong. Please try again.", true);
          refreshToken(); // rotate token for the retry
        }
      })
      .catch(function () {
        showReply("Network error. Please check your connection and try again.", true);
        refreshToken();
      })
      .finally(function () {
        setBusy(false);
      });
  });
})();
