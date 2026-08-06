#!/usr/bin/env python3
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# The Control half of NFR-SEC-52: the agent-facing MCP gateway must have no
# route to the operator ingress (kill-switch, denylist, lifecycle).
#
# Reachability is a PAIR. The gateway repo already asserts it cannot route out;
# this asserts Control does not expose. Until both ends are checked the
# invariant is unfalsifiable from one side, which is the state ocu-control#1
# records.
#
# What this checks is custody, not network membership (ADR-0038). Control's
# operator ingress is a unix socket -- `-operator-listen unix://...` on both
# shelves -- so there is no port to reach and no network rule to inspect. A
# membership assertion here would test a property with no counterpart. The
# properties that actually hold the invariant are: the listener stays a socket,
# nothing publishes it, nothing else mounts it, and no policy admits the
# gateway's identity.
#
# Two-sided by construction: `--self-test` plants each violation and requires
# this script to catch it, then requires the shipped manifests to pass. It runs
# BEFORE the gate in CI, so a check that stopped detecting cannot report green.
import sys
import os

try:
    import yaml
except ImportError:
    print("::error::PyYAML is required (pip install pyyaml)", file=sys.stderr)
    sys.exit(2)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
K8S = os.path.join(REPO, "examples", "k8s", "control-deployment.yaml")
COMPOSE = os.path.join(REPO, "deploy", "docker-compose.yml")

# The deploy identity ADR-0038 fixes. The gateway's egress allowlist selects on
# this exact pair, so a drift here silently unbinds the far side's assertion.
CONTROL_NAME = "ocu-control"
GATEWAY_NAME = "ocu-mcp-gateway"
INGRESS_LABEL = "ocu.dev/ingress"

failures = []


def fail(msg):
    failures.append(msg)


def load(path):
    """Parse a manifest, failing CLOSED on absence or garbage.

    An unreadable manifest must never pass: 'nothing to find' and 'nothing
    found' are the same green, and that is the failure this gate exists to
    prevent.
    """
    if not os.path.exists(path):
        fail(f"{os.path.relpath(path, REPO)} is missing; the gate cannot assert on a manifest that is not there")
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            docs = [d for d in yaml.safe_load_all(fh) if d]
    except yaml.YAMLError as exc:
        fail(f"{os.path.relpath(path, REPO)} is not parseable YAML: {exc}")
        return None
    if not docs:
        fail(f"{os.path.relpath(path, REPO)} parsed to nothing")
        return None
    return docs


def operator_listener_is_a_socket(docs):
    """The operator ingress must stay a unix socket.

    This is the load-bearing property. A tcp:// bind would create the network
    exposure every other assertion here is written around, and it would do so
    without touching a NetworkPolicy -- so no policy check would notice.
    """
    seen = False
    for doc in docs:
        for container in _containers(doc):
            args = container.get("args") or container.get("command") or []
            for i, a in enumerate(args):
                if a == "-operator-listen" or a.startswith("-operator-listen="):
                    seen = True
                    val = a.split("=", 1)[1] if "=" in a else (args[i + 1] if i + 1 < len(args) else "")
                    if not val.startswith("unix://"):
                        fail(
                            f"-operator-listen is {val!r}, not a unix:// socket. A network bind exposes the "
                            f"operator ingress (kill-switch, denylist, lifecycle) to anything that can reach "
                            f"the pod, which is exactly what NFR-SEC-52 forbids."
                        )
    if not seen:
        fail("no -operator-listen flag found; the gate cannot confirm the operator ingress is a socket")


def nothing_publishes_a_listener(docs):
    """No Service, Ingress, NodePort or containerPort exposes Control.

    Both listeners are socket or loopback today. A published port is how that
    silently stops being true.
    """
    for doc in docs:
        kind = doc.get("kind")
        if kind in ("Service", "Ingress"):
            fail(f"a {kind} object exposes Control; both listeners are unix-socket or loopback and must stay unpublished")
        for container in _containers(doc):
            for port in container.get("ports") or []:
                fail(
                    f"containerPort {port.get('containerPort')} is declared on Control. The operator ingress is a "
                    f"socket and the session listener is loopback; declaring a port advertises a surface neither has."
                )


def socket_volume_is_not_shared(docs):
    """Only the Control container mounts the socket's volume.

    A second container mounting it reaches the operator ingress without any
    network at all -- the file-system route the network assertions cannot see.
    """
    for doc in docs:
        spec = _pod_spec(doc)
        if not spec:
            continue
        runtime_mounters = []
        for container in spec.get("containers", []) + spec.get("initContainers", []):
            for m in container.get("volumeMounts") or []:
                if m.get("name") == "runtime":
                    runtime_mounters.append(container.get("name"))
        if len(runtime_mounters) > 1:
            fail(
                f"the runtime volume holding operator.sock is mounted by {runtime_mounters}. Sharing it hands the "
                f"operator ingress to another container over the filesystem, bypassing every network control."
            )


def no_policy_admits_the_gateway(docs):
    """No NetworkPolicy ingress rule selects the gateway's identity.

    The mirror of the gateway's egress assertion. It has no rule to match today
    and must never gain one.
    """
    for doc in docs:
        if doc.get("kind") != "NetworkPolicy":
            continue
        for rule in (doc.get("spec") or {}).get("ingress") or []:
            for peer in rule.get("from") or []:
                for sel_key in ("podSelector", "namespaceSelector"):
                    sel = peer.get(sel_key) or {}
                    if _selector_targets_gateway(sel):
                        fail(
                            f"a NetworkPolicy ingress rule admits {GATEWAY_NAME}. The gateway must have no route to "
                            f"Control's operator ingress (NFR-SEC-52); this rule grants one."
                        )


def _selector_targets_gateway(sel):
    """True if a selector can match the gateway, in any of its three forms."""
    labels = sel.get("matchLabels") or {}
    if labels.get("app.kubernetes.io/name") == GATEWAY_NAME:
        return True
    for expr in sel.get("matchExpressions") or []:
        if expr.get("key") != "app.kubernetes.io/name":
            continue
        op = expr.get("operator")
        # Exists matches every value, the gateway's included.
        if op == "Exists":
            return True
        if op == "In" and GATEWAY_NAME in (expr.get("values") or []):
            return True
    return False


def deploy_identity_is_canonical(docs):
    """Pods carry the identity ADR-0038 fixes, and no false operator label.

    The gateway's allowlist selects on this pair. When Control labelled itself
    ocu-controld the selector matched no pod, so the far side's assertion bound
    against nothing while appearing to work.
    """
    for doc in docs:
        if doc.get("kind") != "Deployment":
            continue
        labels = ((doc.get("spec") or {}).get("template") or {}).get("metadata", {}).get("labels", {})
        name = labels.get("app.kubernetes.io/name")
        if name != CONTROL_NAME:
            fail(
                f"pod label app.kubernetes.io/name is {name!r}, not {CONTROL_NAME!r} (ADR-0038). The gateway's egress "
                f"allowlist selects the canonical name; a divergent label leaves that allowlist matching no pod."
            )
        if labels.get(INGRESS_LABEL) == "operator":
            fail(
                f"a pod carries {INGRESS_LABEL}: operator. No pod may claim that audience while the operator ingress "
                f"is a unix socket (ADR-0038) -- the label asserts a network exposure that does not exist."
            )


def compose_does_not_publish(docs):
    """The Control service publishes no port, and its operator bind is a socket.

    Scoped to the service that RUNS Control, not every service in the file. The
    deployment also ships an nginx sidecar publishing the public JWKS document
    on loopback -- that is a different listener with a different audience, and
    flagging it would make this gate cry wolf about a surface the invariant does
    not cover.
    """
    for doc in docs:
        for svc_name, svc in (doc.get("services") or {}).items():
            if not _is_control_service(svc_name, svc):
                continue
            if svc.get("ports"):
                fail(f"compose service {svc_name!r} runs Control and publishes {svc['ports']}; its listeners must stay unpublished")
            args = svc.get("command") or []
            for i, a in enumerate(args):
                if a == "-operator-listen":
                    val = args[i + 1] if i + 1 < len(args) else ""
                    if not str(val).startswith("unix://"):
                        fail(f"compose service {svc_name!r} binds -operator-listen to {val!r}, not a unix:// socket")


def _is_control_service(name, svc):
    """True for the service running the Control daemon.

    Identified by the flag only it carries, not by its name: a rename would
    otherwise silently take the service out of scope, which is the failure mode
    a name match invites.
    """
    args = svc.get("command") or []
    return any(str(a).startswith("-operator-listen") for a in args)


def _containers(doc):
    spec = _pod_spec(doc)
    if not spec:
        return []
    return spec.get("containers", []) + spec.get("initContainers", [])


def _pod_spec(doc):
    if doc.get("kind") == "Deployment":
        return ((doc.get("spec") or {}).get("template") or {}).get("spec") or {}
    if doc.get("kind") == "Pod":
        return doc.get("spec") or {}
    return None


def check_all():
    failures.clear()
    k8s = load(K8S)
    if k8s:
        operator_listener_is_a_socket(k8s)
        nothing_publishes_a_listener(k8s)
        socket_volume_is_not_shared(k8s)
        no_policy_admits_the_gateway(k8s)
        deploy_identity_is_canonical(k8s)
    compose = load(COMPOSE)
    if compose:
        compose_does_not_publish(compose)
    return list(failures)


def _expect_caught(label, docs, fn):
    """Run one assertion over a planted manifest and require it to complain."""
    failures.clear()
    fn(docs)
    if not failures:
        print(f"::error::self-test: {label} was NOT caught; the gate is blind to it", file=sys.stderr)
        return False
    print(f"  ok: {label} caught")
    return True


def self_test():
    """Plant each violation and require this gate to catch it.

    A gate nobody proves fires is indistinguishable from one that matches
    nothing. Each plant below is a real manifest shape, not a string.
    """
    ok = True
    print("self-test: planting each violation the gate claims to catch")

    ok &= _expect_caught(
        "tcp:// operator listener",
        [{"kind": "Deployment", "spec": {"template": {"spec": {"containers": [
            {"name": "controld", "args": ["-operator-listen", "tcp://0.0.0.0:9443"]}]}}}}],
        operator_listener_is_a_socket)

    ok &= _expect_caught(
        "absent operator-listen flag",
        [{"kind": "Deployment", "spec": {"template": {"spec": {"containers": [
            {"name": "controld", "args": ["-gateway-listen", "127.0.0.1:9466"]}]}}}}],
        operator_listener_is_a_socket)

    ok &= _expect_caught(
        "a Service exposing Control",
        [{"kind": "Service", "metadata": {"name": "ocu-control"}}],
        nothing_publishes_a_listener)

    ok &= _expect_caught(
        "a declared containerPort",
        [{"kind": "Deployment", "spec": {"template": {"spec": {"containers": [
            {"name": "controld", "ports": [{"containerPort": 9443}]}]}}}}],
        nothing_publishes_a_listener)

    ok &= _expect_caught(
        "a second container mounting the socket volume",
        [{"kind": "Deployment", "spec": {"template": {"spec": {"containers": [
            {"name": "controld", "volumeMounts": [{"name": "runtime"}]},
            {"name": "sidecar", "volumeMounts": [{"name": "runtime"}]}]}}}}],
        socket_volume_is_not_shared)

    for form, sel in (
        ("matchLabels", {"matchLabels": {"app.kubernetes.io/name": GATEWAY_NAME}}),
        ("matchExpressions In", {"matchExpressions": [
            {"key": "app.kubernetes.io/name", "operator": "In", "values": [GATEWAY_NAME]}]}),
        ("matchExpressions Exists", {"matchExpressions": [
            {"key": "app.kubernetes.io/name", "operator": "Exists"}]}),
    ):
        ok &= _expect_caught(
            f"NetworkPolicy admitting the gateway via {form}",
            [{"kind": "NetworkPolicy", "spec": {"ingress": [{"from": [{"podSelector": sel}]}]}}],
            no_policy_admits_the_gateway)

    ok &= _expect_caught(
        "a non-canonical pod identity",
        [{"kind": "Deployment", "spec": {"template": {"metadata": {"labels": {
            "app.kubernetes.io/name": "ocu-controld"}}, "spec": {"containers": []}}}}],
        deploy_identity_is_canonical)

    ok &= _expect_caught(
        "a pod claiming the operator audience",
        [{"kind": "Deployment", "spec": {"template": {"metadata": {"labels": {
            "app.kubernetes.io/name": CONTROL_NAME, INGRESS_LABEL: "operator"}},
            "spec": {"containers": []}}}}],
        deploy_identity_is_canonical)

    ok &= _expect_caught(
        "a compose service publishing a port",
        [{"services": {"controld": {
            "command": ["-operator-listen", "unix:///run/ocu-control/operator.sock"],
            "ports": ["9443:9443"]}}}],
        compose_does_not_publish)

    failures.clear()
    shipped = check_all()
    if shipped:
        print("::error::self-test: the SHIPPED manifests do not pass:", file=sys.stderr)
        for f in shipped:
            print(f"  - {f}", file=sys.stderr)
        ok = False
    else:
        print("  ok: the shipped manifests pass")

    if not ok:
        sys.exit(1)
    print("self-test: every planted violation was caught and the shipped manifests pass")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        self_test()
        sys.exit(0)
    problems = check_all()
    if problems:
        print("::error::NFR-SEC-52 (Control side): the manifests permit what the invariant forbids", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        sys.exit(1)
    print("iac-policy: the operator ingress stays a socket, nothing publishes or shares it, "
          "no policy admits the gateway, and the deploy identity is canonical")
