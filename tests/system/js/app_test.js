// Behaviour of static/app.js in jsdom with a mocked fetch.
// node app_test.js /path/to/app.js   (NODE_PATH must contain jsdom)
"use strict";
const fs = require("fs");
const {JSDOM, VirtualConsole} = require("jsdom");

const appJs = fs.readFileSync(process.argv[2], "utf8");
let failures = 0;
function check(name, ok) {
  console.log((ok ? "ok   " : "FAIL ") + name);
  if (!ok) failures += 1;
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const HTML = `<!doctype html><html><body>
<div class="page-head">
  <form id="head" method="post" action="/queue/action" data-async>
    <input type="hidden" name="csrf_token" value="tok">
    <button id="flush" type="submit" name="action" value="flush">Flush</button>
  </form>
</div>
<div class="card"><div id="region" class="live" data-live>
  <form id="bulk" method="post" action="/queue/action" data-async>
    <input type="hidden" name="csrf_token" value="tok">
    <input id="all" type="checkbox" data-select-all="ids">
    <input type="checkbox" name="ids" value="A"><input type="checkbox" name="ids" value="B">
    <button id="hold" type="submit" name="action" value="hold">Hold</button>
    <button id="delete" type="submit" name="action" value="delete" data-confirm="Delete?">Delete</button>
  </form>
</div></div>
<form id="plain" method="post" action="/somewhere"><button id="plainbtn" type="submit">Go</button></form>
</body></html>`;

function setup(respond) {
  const errors = [];
  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", (e) => errors.push(String(e.message || e)));
  const dom = new JSDOM(HTML, {url: "https://gw.example/queue/?x=1", runScripts: "outside-only",
                               pretendToBeVisual: true, virtualConsole});
  const w = dom.window;
  const calls = [];
  w.fetch = (url, options) => {
    calls.push({url: String(url), options});
    return respond(calls.length, String(url), options);
  };
  w.__confirm = true;
  w.confirm = () => w.__confirm;
  // Browsers let form controls shadow the form's properties: with buttons
  // named "action", form.action is a RadioNodeList, not the URL. jsdom does
  // not, so do it here.
  w.document.querySelectorAll("form").forEach((form) => {
    const named = form.elements.namedItem("action");
    if (named) {
      Object.defineProperty(form, "action", {get: () => named});
    }
  });
  w.eval(appJs);
  return {dom, w, d: w.document, calls, errors};
}

function fragment(html, url) {
  return Promise.resolve({
    ok: true, status: 200, url: url || "https://gw.example/queue/?x=1",
    headers: {get: (name) => (name === "X-Live-Fragment" ? "1" : null)},
    text: () => Promise.resolve(html),
  });
}

(async () => {
  // --- select all, in-place submit, confirmation ----------------------------
  {
    const t = setup(() => fragment('<div class="flashes"><div class="alert success">Messages put on hold.</div></div>'
                                   + '<p id="new">fresh</p>'));
    const {d, w, calls} = t;
    d.getElementById("all").click();
    check("select all checks the boxes",
          [...d.querySelectorAll('input[name="ids"]')].every((b) => b.checked));
    d.querySelector('input[name="ids"][value="B"]').checked = false;

    d.getElementById("bulk").requestSubmit(d.getElementById("hold"));
    await sleep(20);
    check("in-place submit posts once", calls.length === 1 && calls[0].options.method === "POST");
    check("to the form's action", calls[0].url === "https://gw.example/queue/action");
    check("with the fragment header", calls[0].options.headers["X-Live-Fragment"] === "1");
    const body = calls[0].options.body;
    check("with csrf token, the pressed button and the selection",
          body.get("csrf_token") === "tok" && body.get("action") === "hold"
          && JSON.stringify(body.getAll("ids")) === '["A"]');
    check("region shows the answer with its message",
          d.getElementById("new") !== null && d.getElementById("region").textContent.includes("put on hold"));
    check("focus moves to the region", d.activeElement === d.getElementById("region"));
    check("region not busy afterwards", !d.getElementById("region").hasAttribute("aria-busy"));

    // forms outside the region update it as well
    d.getElementById("head").requestSubmit(d.getElementById("flush"));
    await sleep(20);
    check("page-head form updates the region", calls.length === 2 && calls[1].options.body.get("action") === "flush");

    // a declined confirmation sends nothing
    t.d.getElementById("region").innerHTML = HTML.split('<div id="region" class="live" data-live>')[1]
      .split("</div></div>")[0];
    w.__confirm = false;
    d.getElementById("bulk").requestSubmit(d.getElementById("delete"));
    await sleep(20);
    check("declined confirmation: nothing sent", calls.length === 2);
    w.__confirm = true;
    d.getElementById("bulk").requestSubmit(d.getElementById("delete"));
    await sleep(20);
    check("confirmed: sent", calls.length === 3 && calls[2].options.body.get("action") === "delete");

    // forms without data-async are not intercepted
    let plainSubmitted = false;
    d.getElementById("plain").addEventListener("submit", (e) => { plainSubmitted = !e.defaultPrevented; e.preventDefault(); });
    d.getElementById("plainbtn").click();
    check("other forms submit normally", plainSubmitted && calls.length === 3);
    t.dom.window.close();
  }

  // --- a non-fragment answer (e.g. the login page) is shown as a page -------
  {
    const t = setup(() => Promise.resolve({ok: true, status: 200, url: "https://gw.example/login?next=%2Fqueue%2F",
                                           headers: {get: () => null}, text: () => Promise.resolve("<html>")}));
    t.d.getElementById("bulk").requestSubmit(t.d.getElementById("hold"));
    await sleep(20);
    check("login page: browser navigates there",
          t.errors.some((e) => e.includes("navigation")) && !t.d.getElementById("region").innerHTML.includes("<html>"));
    t.dom.window.close();
  }

  // --- a failed request is reported, not repeated ---------------------------
  {
    const t = setup(() => Promise.reject(new Error("network down")));
    t.d.getElementById("bulk").requestSubmit(t.d.getElementById("hold"));
    await sleep(20);
    const alert = t.d.querySelector("#region .alert.danger[role=alert]");
    check("failure shown in the region", alert !== null && alert.textContent.includes("Reload the page"));
    check("buttons usable again", !t.d.getElementById("hold").disabled);
    check("not repeated", t.calls.length === 1);
    t.dom.window.close();
  }

  // --- no periodic refresh -------------------------------------------------
  {
    const t = setup(() => fragment("<p>x</p>"));
    await sleep(1300);
    check("no periodic refresh", t.calls.length === 0 && t.d.querySelector(".live-status") === null);
    t.dom.window.close();
  }

  // --- one checkbox of a group stays checked (IP families) -----------------
  {
    const t = setup(() => fragment(""));
    const form = t.d.createElement("form");
    form.innerHTML = '<input type="checkbox" id="v4" data-keep-one="ip" data-keep-one-message="Keep one" checked>'
      + '<input type="checkbox" id="v6" data-keep-one="ip" checked>';
    t.d.body.appendChild(form);
    const v4 = t.d.getElementById("v4"), v6 = t.d.getElementById("v6");
    v4.click();
    check("one family can be turned off", !v4.checked && v6.checked);
    v6.click();
    check("the last one stays on", v6.checked && !v4.checked);
    v4.click();
    v6.click();
    check("then the other can be turned off", v4.checked && !v6.checked);
    t.dom.window.close();
  }

  console.log(`failures: ${failures}`);
  process.exit(failures ? 1 : 0);
})();
