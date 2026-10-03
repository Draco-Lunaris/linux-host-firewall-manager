# Security Policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub: open the **Security** tab of this repository and choose **Report a vulnerability**. The report is visible only to the maintainers.

A useful report includes:

- the version, and whether the problem is in the manager or the agent
- the steps to reproduce it
- what an attacker gains

## What to expect

- An acknowledgement within [10 business days].
- An assessment, and a plan for a fix, within [20 days].
- A published advisory once a fix is released, with credit to the reporter unless they ask otherwise.

## Supported versions

[Which versions receive security fixes.]

## Scope

In scope: the manager (`fw-web`, `fw-worker`), the agent (`fw-agent`), the certificate authority (`fw-ca`), and the release packages.

The design this project is meant to hold to is described under [Security model](README.md#security-model) in the README. A way to break one of those properties is exactly the kind of report we want.
