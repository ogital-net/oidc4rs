import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { chromium } from "playwright";

const database = join(homedir(), ".pki", "nssdb");
mkdirSync(database, { recursive: true });
execFileSync("certutil", ["-N", "--empty-password", "-d", `sql:${database}`]);
execFileSync("certutil", [
  "-A", "-d", `sql:${database}`, "-n", "oidc4rs test CA", "-t", "C,,",
  "-i", "/tls/ca.crt",
]);

const browser = await chromium.launch();
try {
  const page = await browser.newPage();
  page.setDefaultTimeout(20_000);
  const [authorization] = await Promise.all([
    page.waitForRequest((request) => {
      const { hostname, pathname } = new URL(request.url());
      return hostname === "keycloak" && pathname === "/realms/interop/protocol/openid-connect/auth";
    }),
    page.goto("http://rp:8080/login", { waitUntil: "domcontentloaded" }),
  ]);
  const scopes = new URL(authorization.url()).searchParams.get("scope");
  assert.deepEqual(scopes?.split(" ").sort(), ["email", "openid", "profile"]);
  await page.locator("#username").fill("interop-user");
  await page.locator("#password").fill("interop-test-only");
  const [callback] = await Promise.all([
    page.waitForResponse((response) => {
      const { origin, pathname } = new URL(response.url());
      return origin === "http://rp:8080" && pathname === "/callback";
    }),
    page.locator("#kc-login").click(),
  ]);
  assert.equal(callback.status(), 200, "the RP must accept the callback");
  const result = await callback.json();
  assert.equal(result.subject, "bca87614-8100-404a-b7e8-983539cdb5c4");
  assert.equal(result.userinfo_subject, result.subject);
  assert.equal(result.name, "Interop User");
  assert.equal(result.email, "interop@example.test");
  assert.equal(result.email_verified, true);
  assert.equal(result.middle_name, null, "an omitted profile claim must not fail login");
  console.log("PASS: Keycloak authorization code + S256 PKCE verified the subject and scoped UserInfo claims");
} finally {
  await browser.close();
}