// Small progressive enhancements, the UI works without JavaScript.
(function () {
  "use strict";

  // Ask before destructive actions: <form data-confirm="..."> or
  // <button data-confirm="..."> inside a form.
  document.addEventListener("submit", function (event) {
    var form = event.target;
    var submitter = event.submitter;
    var message = (submitter && submitter.getAttribute("data-confirm")) || form.getAttribute("data-confirm");
    if (message && !window.confirm(message)) {
      event.preventDefault();
    }
  });

  // "Select all" checkboxes: <input type="checkbox" data-select-all="name">
  // (delegated: live regions replace their content)
  document.addEventListener("change", function (event) {
    var toggle = event.target;
    if (!toggle.matches || !toggle.matches("[data-select-all]")) {
      return;
    }
    var name = toggle.getAttribute("data-select-all");
    var scope = toggle.form || document;
    scope.querySelectorAll('input[type="checkbox"][name="' + name + '"]').forEach(function (box) {
      box.checked = toggle.checked;
    });
  });

  // At least one checkbox of a group stays checked:
  // <input type="checkbox" data-keep-one="group" data-keep-one-message="...">
  document.addEventListener("change", function (event) {
    var box = event.target;
    var group = box.getAttribute && box.getAttribute("data-keep-one");
    if (!group || box.checked) {
      return;
    }
    var scope = box.form || document;
    if (scope.querySelector('input[data-keep-one="' + group + '"]:checked') === null) {
      box.checked = true;
      box.setCustomValidity(box.getAttribute("data-keep-one-message") || "Keep one of these on.");
      box.reportValidity();
      box.setCustomValidity("");
    }
  });

  // Submit filter selects on change: <select data-autosubmit>
  document.addEventListener("change", function (event) {
    var select = event.target;
    if (select.matches && select.matches("select[data-autosubmit]") && select.form) {
      select.form.submit();
    }
  });

  // Theme toggle: switch immediately instead of submitting the form.
  // The cookie lets the server render the right theme on the next page load.
  var THEMES = ["system", "light", "dark"];
  var LABELS = {system: "◐ System theme", light: "☀ Light theme", dark: "☾ Dark theme"};
  document.querySelectorAll("form[data-theme-toggle]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      var button = form.querySelector("button[name=theme]");
      var chosen = button.value;
      var secure = window.location.protocol === "https:" ? "; Secure" : "";
      document.cookie = "sf_theme=" + chosen + "; Max-Age=31536000; Path=/; SameSite=Lax" + secure;
      if (chosen === "system") {
        document.documentElement.removeAttribute("data-theme");
      } else {
        document.documentElement.setAttribute("data-theme", chosen);
      }
      var next = THEMES[(THEMES.indexOf(chosen) + 1) % THEMES.length];
      button.value = next;
      button.textContent = LABELS[chosen];
      button.title = "Switch to " + next + " theme";
      button.setAttribute("aria-label", "Theme: " + chosen + ", switch to " + next);
    });
  });

  // Toggle the MX hint depending on the "use MX" checkbox
  var useMx = document.getElementById("use_mx");
  var portHint = document.getElementById("mx-hint");
  if (useMx && portHint) {
    var update = function () { portHint.hidden = !useMx.checked; };
    useMx.addEventListener("change", update);
    update();
  }

  // ---------------------------------------------------------------------
  // Live regions: <div data-live>
  //
  // The server renders only the region when asked with the header
  // X-Live-Fragment: 1 (views.render_live). Forms with data-async are
  // submitted in the background: the handler's redirect back to the page
  // keeps the header, so the response is the updated region including the
  // flashed messages.
  // Anything else (expired session, error page) is shown as a normal page.
  // ---------------------------------------------------------------------
  var FRAGMENT = "X-Live-Fragment";

  function fetchRegion(region, url, options) {
    options = options || {};
    options.credentials = "same-origin";
    options.headers = {};
    options.headers[FRAGMENT] = "1";
    region.setAttribute("aria-busy", "true");
    region.classList.add("is-loading");
    return window.fetch(url, options).then(function (response) {
      if (response.headers.get(FRAGMENT) !== "1") {
        // e.g. redirected to the login page: show it
        window.location.assign(response.url);
        return null;
      }
      if (!response.ok) {
        throw new Error("HTTP " + response.status);
      }
      return response.text().then(function (html) {
        region.innerHTML = html;
        return region;
      });
    }).finally(function () {
      region.removeAttribute("aria-busy");
      region.classList.remove("is-loading");
    });
  }

  // In-place forms: after the confirmation handler above (registered first)
  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (event.defaultPrevented || !form.hasAttribute || !form.hasAttribute("data-async") || !window.fetch) {
      return;
    }
    var region = form.closest("[data-live]") || document.querySelector("[data-live]");
    if (!region) {
      return;
    }
    event.preventDefault();
    var data = new FormData(form);
    var submitter = event.submitter;
    if (submitter && submitter.name) {
      data.append(submitter.name, submitter.value);
    }
    form.querySelectorAll("button").forEach(function (button) { button.disabled = true; });
    // Not form.action: controls named "action" (the buttons of the queue and
    // quarantine forms) shadow that property
    var url = new URL(form.getAttribute("action") || window.location.href, window.location.href).href;
    fetchRegion(region, url, {method: "POST", body: data}).then(function (updated) {
      if (updated) {
        region.setAttribute("tabindex", "-1");
        region.focus({preventScroll: true});
      }
    }).catch(function () {
      // Whether the action was carried out is unknown: say so instead of repeating it
      form.querySelectorAll("button").forEach(function (button) { button.disabled = false; });
      var alert = document.createElement("div");
      alert.className = "alert danger";
      alert.setAttribute("role", "alert");
      alert.textContent = "The server did not answer as expected. Reload the page to see whether the action was carried out.";
      region.insertBefore(alert, region.firstChild);
    });
  });

  // Unsaved changes: <form data-dirty-warn> gets the class "dirty" once a
  // field changes (its .save-bar says so), and leaving the page asks first.
  // Registered after the confirmation above: a cancelled submit stays dirty.
  var leaving = false;
  function markDirty(event) {
    var form = event.target.form;
    if (form && form.hasAttribute("data-dirty-warn")) {
      form.classList.add("dirty");
    }
  }
  document.addEventListener("input", markDirty);
  document.addEventListener("change", markDirty);
  document.addEventListener("submit", function (event) {
    if (!event.defaultPrevented && event.target.hasAttribute("data-dirty-warn")) {
      leaving = true;
    }
  });
  window.addEventListener("beforeunload", function (event) {
    if (!leaving && document.querySelector("form[data-dirty-warn].dirty")) {
      event.preventDefault();
      event.returnValue = "";
    }
  });
})();
