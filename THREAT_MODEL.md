# terraform-aws-lambda threat model

## Overview

Terraform module builds local source into a content-named ZIP and creates Lambda plus execution IAM. Python packaging installs requirements through host pip; callers supply handler/runtime and optional environment, VPC, DLQ, layers and policy (archive.tf:3, build.py:133, lambda.tf:1).

| Component | Source |
| --- | --- |
| Lambda function and optional runtime blocks | lambda.tf:1 |
| Role and conditional policies | iam.tf:3 |
| Archive/build/cache pipeline | archive.tf:3; hash.py:137; build.py:102; built.py:18 |

| Deployment or workflow | Resource or capability | Configuration and precedence | Safe effective value or location | Readers, writers, or recipients | Enforcing control | Evidence or unknowns |
| --- | --- | --- | --- | --- | --- | --- |
| normal build and missing-cache rebuild | ZIP artifact | source file contents/relative names + runtime + build script contents → SHA256; built result → Lambda filename | <runner cwd>/.terraform/terraform-aws-lambda-<64 hex SHA256>.zip | Runner and AWS Lambda upload | Filesystem permissions; filename change trigger; missing cache rebuild, seven-day matched archive cleanup | hash.py:137; hash.py:146; hash.py:33; built.py:18; lambda.tf:15 |
| default build.py | Build workspace | source copied into tempfile.mkdtemp prefix; Python requirements → pip2/pip3 install -t . → zip | OS temporary directory terraform-aws-lambda-* removed in finally; ZIP persists in runner .terraform | Host subprocesses, package index dependencies and Lambda artifact | Host OS authority; no container isolation; custom script can replace build behavior | build.py:80; build.py:122; build.py:133 |
| all deployed functions | Execution role | function_name + trusted_entities + optional policy | Role ${function_name}; lambda.amazonaws.com plus added service principals; caller policy JSON optional | Lambda/service principals allowed by trust | AWS IAM trust and attached policies | iam.tf:3; iam.tf:138 |
| optional environment/VPC/DLQ | Runtime data | non-null objects directly instantiate corresponding Lambda blocks | Environment variables; caller subnet/security-group IDs; caller target_arn | Lambda process; configured VPC; SNS/SQS destination | VPC/IAM and target-scoped dead-letter grants | lambda.tf:20; lambda.tf:27; lambda.tf:41; iam.tf:69 |
| default/caller overrides | Logs and limits | cloudwatch_logs true default; timeout 10; concurrency null | /aws/lambda/${function_name}; log writes current partition/account/region; no log retention resource | CloudWatch readers and Lambda writer | Built-in scoped stream/event grant; callers own retention and additional grants | iam.tf:23; variables.tf:23; variables.tf:40; variables.tf:106 |

## Threat Model, Trust Boundaries, and Assumptions

Protected assets: Runner filesystem/credentials and executable dependency supply chain; ZIP/code integrity; Lambda role, environment, logs and dead-letter payloads (build.py:122, lambda.tf:27, iam.tf:69).

The Terraform caller trusts source_path and optional build_script as local build inputs. The default builder copies files into a temporary directory, installs Python requirements with host pip and runs zip. A custom builder replaces that behavior. This boundary inherits runner filesystem, subprocess and available credential authority; it does not isolate package installation or compile inside the selected Lambda runtime (archive.tf:9, build.py:122, build.py:133).

Build execution is not confined to resource creation. The external built helper invokes a shell command when the expected cached archive is missing and the old/new names match; hash evaluation also removes aged matching archives. Runners performing a supposedly read-only plan must account for these local effects. The source hash is not an independently verified digest of uploaded package bytes (built.py:18, hash.py:165, lambda.tf:15).

The AWS deployment identity and runtime execution role are distinct. The role trusts Lambda plus caller-provided service principals. Additional policy JSON is applied verbatim; logging, DLQ and VPC grants are component-owned additions. AWS event invocation policies, application authorization and external targets remain caller-owned (iam.tf:3, iam.tf:69, iam.tf:103, iam.tf:138).

The README usage source points to claranet rather than necessarily this fork. Its lambda_at_edge/attach_vpc_config guidance does not describe the local control: trusted_entities extends service trust, and vpc_config nullness controls both runtime VPC settings and ENI policy. attach_dead_letter_config is declared but the DLQ block follows object nullness. No function publication/alias, Cloudflare or event source is configured. Tests demonstrate deployments, not production exposure (README.md:23, README.md:52, README.md:70, lambda.tf:20, lambda.tf:41, variables.tf:78).

## Attack Surface, Mitigations, and Attacker Stories

These are prioritized hypotheses for review, not confirmed vulnerabilities. Each depends on the stated actor and deployment prerequisites.

| Priority | Scenario and capability gain | Prerequisites | Impact | Existing controls | Mitigation | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| P1 | A dependency or custom builder could turn accepted build input into runner code execution. | Untrusted code/configuration reaches a privileged Terraform evaluation/build host. | Credential disclosure, altered ZIPs or unauthorized operations with runner authority. | Inputs are operator configuration; no remote build API is present. | Review/pin build inputs and run builds with narrowly scoped credentials and filesystem access. | archive.tf:9; build.py:133; built.py:31 |
| P1 | Overbroad caller policy or added service trust could expose workload authority to unintended principals. | Caller supplies such policy/trust or an external invocation path reaches privileged application code. | Unauthorized AWS actions or sensitive-data access. | Lambda service trust always present; built-in DLQ target is scoped and log writes target function group. | Review effective role trust/policy and application invocation controls at consuming root. | iam.tf:10; iam.tf:80; iam.tf:138 |
| P2 | A cached ZIP could be replaced independently of the source-derived filename. | An actor can write the runner cache but does not already control trusted source or deployment. | Code upload differs from reviewed source. | Cache filename changes with source/runtime/builder; existing cache is checked for existence and touched. | Protect cache ownership and verify artifacts across privilege-changing pipeline stages. | hash.py:137; built.py:18; lambda.tf:15 |
| P2 | Sensitive environment or failed-event payloads could reach unintended readers or DLQ recipients. | A consuming application supplies sensitive values/events and accessible state/log/DLQ destinations. | Disclosure of workload data. | DLQ send permissions target supplied ARN; environment is explicit configuration. | Keep secret/state access restricted and choose audited target/log retention policies. | lambda.tf:20; lambda.tf:27; iam.tf:69 |

## Severity Calibration (Critical, High, Medium, Low)

**Critical.** Critical requires evidence of a broad consequential deployment compromise, such as untrusted build execution exposing administrative credentials. The existence of a trusted custom-builder hook is not enough.

**High.** High fits a demonstrated transition from lower-trust source/cache input to privileged deployment or from unauthorized invocation to meaningful runtime AWS authority. Caller policy and pipeline ownership must be established.

**Medium.** Medium fits bounded secret disclosure, cross-stage artifact mismatch or material rebuild/deployment interruption where the actor and permissions are proven. A missing local cache that the helper repairs is expected behavior.

**Low.** Low fits harmless build diagnostics or recoverable local packaging failures. No public HTTP service or tenant boundary exists in the module; application-level severity needs a real caller.

This is an offline, source-backed architecture review. No application execution, cloud state inspection or vulnerability validation was performed.

Repository: https://github.com/mathspace/terraform-aws-lambda
Version: 9b49bc2d113b8b8696a7f138845381c55c1cd70d
