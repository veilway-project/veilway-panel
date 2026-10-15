# Security policy

The panel holds the keys to a node's users, so a vulnerability here can expose the people who use it, or the node itself. Reports are taken seriously and handled in private.

## Reporting a vulnerability

Report it through GitHub's private form:

https://github.com/veilway-project/veilway-panel/security/advisories/new

The report is visible only to you and the project maintainers. The project has no security email address yet, so this form is the only private channel.

**Do not open a public issue, pull request or Discussions thread for a vulnerability**, and do not post details in a commit message. If you are not sure whether something is a security problem, report it privately anyway.

Please include what you can of:

- the version or commit, the operating system, and which part is affected (server or web app);
- what an attacker needs (network position, a valid account, a valid device, a crafted request) and what they gain;
- steps or a proof of concept that reproduces it.

Remove real server addresses, keys, passwords, tokens and subscription links before you send anything. Use `example.com` and addresses from `192.0.2.0/24`, `198.51.100.0/24` or `203.0.113.0/24` in examples.

## What happens next

| Step | Time |
|---|---|
| We confirm that we received the report | within 7 days |
| We tell you whether we can reproduce it and how serious we think it is | within 14 days |
| Fix released for a confirmed vulnerability | as fast as it can be done properly; we aim for 30 days and tell you if it will take longer |

We keep you informed while the fix is in progress, agree a disclosure date with you, and publish an advisory when the fix is out. You are credited in the advisory and the release notes under the name you choose, or not at all if you prefer. Please give us up to 90 days before publishing details yourself; if users are already being attacked, tell us and we will move faster.

There is no paid bounty.

## Supported versions

The panel is pre-1.0. Only the latest release and the `main` branch receive security fixes.

## Scope

In scope: everything in this repository, including the server in `server/`, the web app in `web/`, the subscription endpoint, the admin API and the files the panel writes (the database, the key files and the audit log).

Things we particularly want to hear about:

- a way past sign-in, two-factor, sessions, CSRF or re-authentication;
- a token or a session that reaches a route it should not;
- a way to read a key, a token, a subscription link or a user's details without the right access;
- a way to confirm a subscription endpoint from its answer, when it should look like an unknown path;
- crashes, memory exhaustion or code execution from network input, requests, subscription data or node answers;
- anything that changes a node's users or settings without the admin's action.

Vulnerabilities in third-party dependencies are best reported upstream first. Tell us too if the panel's use of the dependency makes the problem exploitable.

## Good faith

We will not pursue or support legal action against anyone who finds and reports a problem in good faith, stays within their own systems and accounts or ones they have permission to test, and does not access other people's data or disrupt their service.
