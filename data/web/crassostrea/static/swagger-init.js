// Initialises Swagger UI on /api/docs (inline scripts are blocked by the CSP).
window.addEventListener("DOMContentLoaded", function () {
  "use strict";
  var element = document.getElementById("swagger-ui");
  window.SwaggerUIBundle({
    url: element.getAttribute("data-spec-url"),
    dom_id: "#swagger-ui",
    deepLinking: true,
    persistAuthorization: false,
    tryItOutEnabled: false
  });
});
