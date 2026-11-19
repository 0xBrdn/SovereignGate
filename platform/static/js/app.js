/* SovereignGate UI behaviour.
 * Vanilla ES2018, no build step, no eval and no inline handlers, so the
 * strict Content-Security-Policy (script-src 'self') can stay in place.
 * Progressive enhancement: every page works as plain HTML without it.
 */
(function () {
  "use strict";

  var drawer = document.getElementById("drawer");
  var drawerBody = document.getElementById("drawer-body");
  var live = document.getElementById("live-region");
  var lastTrigger = null;
  var LOADING_HTML = '<div class="drawer__loading" role="status">Loading evidence…</div>';

  /* ---- Drawer ---------------------------------------------------------- */
  function openDrawer(url, trigger) {
    if (!drawer || !drawerBody || typeof drawer.showModal !== "function") {
      window.location.assign(url);
      return;
    }
    lastTrigger = trigger || document.activeElement;
    drawerBody.innerHTML = LOADING_HTML;
    if (!drawer.open) drawer.showModal();
    window.htmx.ajax("GET", url, { target: "#drawer-body", swap: "innerHTML" });
  }

  function closeDrawer() {
    if (drawer && drawer.open) drawer.close();
  }

  if (drawer) {
    drawer.addEventListener("close", function () {
      drawerBody.innerHTML = LOADING_HTML;
      if (lastTrigger && typeof lastTrigger.focus === "function") lastTrigger.focus();
    });
    // Click on the backdrop (the <dialog> element itself) closes the drawer.
    drawer.addEventListener("click", function (event) {
      if (event.target === drawer) closeDrawer();
    });
  }

  document.addEventListener("click", function (event) {
    var closer = event.target.closest("[data-drawer-close]");
    if (closer) { closeDrawer(); return; }

    var row = event.target.closest("[data-finding-url]");
    if (row && !event.target.closest("a[href]:not([data-drawer-link])")) {
      event.preventDefault();
      openDrawer(row.getAttribute("data-finding-url"), row.querySelector("[data-drawer-link]") || row);
    }
  });

  /* Server may reject a triage decision (403) or validation (422): show the
     returned fragment instead of silently dropping it. */
  document.body.addEventListener("htmx:beforeSwap", function (event) {
    var status = event.detail.xhr && event.detail.xhr.status;
    if (status === 403 || status === 422) {
      event.detail.shouldSwap = true;
      event.detail.isError = false;
    }
  });

  document.body.addEventListener("htmx:responseError", function (event) {
    var target = event.detail.target;
    if (target && target.id === "drawer-body") {
      target.innerHTML = '<div class="drawer__loading" role="alert">The request could not be completed (HTTP ' +
        event.detail.xhr.status + "). Close this panel and try again.</div>";
    }
  });

  /* ---- Announce table updates to assistive tech ------------------------ */
  document.body.addEventListener("htmx:afterSettle", function (event) {
    var el = event.detail.elt;
    if (el && el.id === "findings-table-container" && live) {
      var count = el.getAttribute("data-count");
      live.textContent = count === null ? "" : count + " findings shown";
    }
  });

  /* ---- Tenant menu: close on outside click / Escape -------------------- */
  document.addEventListener("click", function (event) {
    document.querySelectorAll("details.menu[open]").forEach(function (menu) {
      if (!menu.contains(event.target)) menu.removeAttribute("open");
    });
  });
  document.addEventListener("keydown", function (event) {
    if (event.key !== "Escape") return;
    document.querySelectorAll("details.menu[open]").forEach(function (menu) {
      menu.removeAttribute("open");
      var summary = menu.querySelector("summary");
      if (summary) summary.focus();
    });
  });

  /* ---- Section nav: highlight the section being read ------------------- */
  var tabs = Array.prototype.slice.call(document.querySelectorAll(".tabs a[href^='#']"));
  if (tabs.length && "IntersectionObserver" in window) {
    var map = {};
    tabs.forEach(function (a) { map[a.getAttribute("href").slice(1)] = a; });
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        tabs.forEach(function (a) { a.removeAttribute("aria-current"); });
        var active = map[entry.target.id];
        if (active) active.setAttribute("aria-current", "true");
      });
    }, { rootMargin: "-20% 0px -65% 0px" });
    Object.keys(map).forEach(function (id) {
      var section = document.getElementById(id);
      if (section) observer.observe(section);
    });
  }
})();
