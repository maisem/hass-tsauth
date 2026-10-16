/* Native HA authorize-page restart bridge. No identity proof is handled here. */
(() => {
  "use strict";
  if (window.location.pathname !== "/auth/authorize") return;
  if (window.__tsidpAuthorizeBridgeInstalled) return;
  window.__tsidpAuthorizeBridgeInstalled = true;

  // Filter only our flags. Never round-trip OAuth state/redirect bytes through
  // URLSearchParams, which would normalize the original encoded query.
  const query = window.location.search.slice(1).split("&").filter((part) => {
    let key = part.split("=", 1)[0];
    try {
      key = decodeURIComponent(key.replace(/\+/g, " "));
    } catch (_) {
      // Leave malformed unrelated parameters for the server to validate.
    }
    return key !== "tsidp_local" && key !== "tsidp_resume";
  }).join("&");
  const start = "/auth/tsidp/start" + (query ? "?" + query : "");
  let restarting = false;
  const restart = () => {
    if (restarting) return;
    restarting = true;
    window.location.assign(start);
  };

  // The pinned native chooser emits a composed AuthProvider detail. Capture
  // before ha-authorize starts a ticketless flow; leave other providers alone.
  window.addEventListener("pick-auth-provider", (event) => {
    if (event.detail?.type !== "tsidp") return;
    event.preventDefault();
    event.stopImmediatePropagation();
    restart();
  }, true);

  const fetch = window.fetch;
  window.fetch = async function (input, init) {
    const response = await fetch.call(window, input, init);
    try {
      const request = input instanceof Request ? input : null;
      const url = new URL(request ? request.url : input, window.location.href);
      const method = (init?.method || request?.method || "GET").toUpperCase();
      if (
        method === "POST" &&
        url.origin === window.location.origin &&
        url.pathname === "/auth/login_flow" &&
        !url.search
      ) {
        // A clone is essential: HA must still be able to read its response.
        const result = await response.clone().json();
        if (
          result?.type === "abort" &&
          Array.isArray(result.handler) &&
          result.handler[0] === "tsidp" &&
          result.reason === "restart_sso"
        ) restart();
      }
    } catch (_) {
      // Malformed/non-JSON responses remain owned by HA's normal error UI.
    }
    return response;
  };
})();
