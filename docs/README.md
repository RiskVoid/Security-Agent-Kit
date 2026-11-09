# RiskVoid Security Agent Kit documentation

The kit is a self-hosted AI security assistant for authorised work: code, dependency and secrets review, and web,
API, AI application and external network testing, with sandboxed tools, human approvals, verified evidence and a
client-ready report. These pages cover everything from the first install to running client engagements and
changing how the kit works.

New here? Read [What the kit is](overview.md), then [Getting started](getting-started.md), then
[Your first engagement](first-engagement.md) (about 20 minutes, against the practice lab).

## Learn

| Page | What it covers |
|---|---|
| [What the kit is](overview.md) | Capabilities, the kinds of work it does, safety controls, what it isn't, key terms |
| [Architecture and design](architecture.md) | Services, networks, how one task flows through the system, trust boundaries, design decisions |

## Set up

| Page | What it covers |
|---|---|
| [Getting started](getting-started.md) | Requirements, install, `./rvkit setup`, checking the stack, the first conversation |
| [Models](models.md) | Planner and worker, Colab / local / API workers, the fallback, budget and costs, where your data goes |
| [Configuration reference](configuration.md) | Every `.env` setting and the other files you can change |

## Do the work

| Page | What it covers |
|---|---|
| [Your first engagement](first-engagement.md) | A guided run against OWASP Juice Shop in the isolated lab |
| [Engagements](engagements.md) | Creating engagements, scope and rules, tiers, approvals, halting, the audit log, close-out |
| [The console](console.md) | The local web page for engagements, approvals, findings triage, reports and the audit log |
| [Working with the agent](running-the-agent.md) | Prompts for each kind of test, what the agent does, monitoring, steering, resuming and re-running |
| [Findings and reports](findings-and-reports.md) | Finding statuses, evidence and its verification, the report, DRAFT checks, branding |
| [Tools reference](tools-reference.md) | Every agent tool, the Kali toolbox with tiers, `rv-llm`, Joern, playbooks, adding your own |
| [Practice lab and benchmarks](lab-and-benchmarks.md) | Vulnerable practice targets, scoring the agent on known targets |
| [Authenticated testing](authenticated-testing.md) | Test accounts per role and tenant, request captures, the sandboxed browser, authorization matrices |
| [Laravel](laravel.md) | The complete source-plus-staging workflow: application map, build check, optional PHP profile |
| [Capability baselines](capability-baselines.md) | What each stack is tested and measured for, and what isn't supported |
| [Regression matrix](regression-matrix.md) | Each safety control and the test that fails if it breaks |

## Run and fix

| Page | What it covers |
|---|---|
| [rvkit command reference](cli-reference.md) | Every command and option |
| [Operating the kit](operations.md) | Daily routine, updates, ports, data and backups, resetting, uninstalling, Linux |
| [Troubleshooting and FAQ](troubleshooting.md) | Symptoms and fixes, common questions |

## Project

- [Security policy and known limitations](../SECURITY.md): read this before client work.
- [How the kit compares](comparison.md) with other open-source AI pentest agents.
- [Roadmap](../ROADMAP.md) and [changelog](../CHANGELOG.md).
- [Third-party components and licences](../THIRD_PARTY.md)
- [Contributing](../CONTRIBUTING.md): development setup, tests, releases.
- [Licence](../LICENSE): Apache-2.0.

## Common tasks

| I want to… | Go to |
|---|---|
| install the kit | [Getting started](getting-started.md) |
| start or stop the Colab model | [Models](models.md#option-1-google-colab-default) |
| use my own GPU or a hosted model | [Models](models.md#option-2-a-local-server-on-this-machine) |
| create an engagement for a client | [Engagements](engagements.md#creating-an-engagement) |
| add a target or allow intrusive tests | [Engagements](engagements.md#changing-scope-and-rules) |
| approve a command the agent is waiting on | [Engagements](engagements.md#approvals) |
| stop everything right now | `./rvkit halt <engagement>`, see [Engagements](engagements.md#halt-and-resume) |
| know what to type to the agent | [Working with the agent](running-the-agent.md#templates) |
| continue an engagement in a new conversation | [Working with the agent](running-the-agent.md#picking-up-again) |
| retest after the client's fixes | [Working with the agent](running-the-agent.md#retest-after-client-fixes) |
| get the report out of DRAFT | [Findings and reports](findings-and-reports.md#draft-or-final) |
| put my company's logo on the report | [Findings and reports](findings-and-reports.md#branding) |
| keep client data off cloud models | [Models](models.md#where-your-data-goes) |
| update the kit | [Operating the kit](operations.md#updating) |
| back up my work | [Operating the kit](operations.md#data-and-backups) |
| fix something that doesn't work | [Troubleshooting](troubleshooting.md) |

Use the kit only on systems you own or have written permission to test.
