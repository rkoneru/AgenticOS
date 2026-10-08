"""Seed for the console's REAL-STACK evals suite (apps/console/e2e-real/evals.spec.ts). NOT a test.

Run against a stack booted by ``interfaces_stack.py`` (``STACK_JSON``): provisions a tenant, publishes blueprint v1 (passes, released,
baseline) and v2 (regresses, blocked), starts a REAL eval runner, leaves one run waiting for a human grade, one run with hostile
output, and some online samples. Prints one JSON line with what the browser needs, then stays alive (the runner is its child) until
SIGTERM.
"""

from __future__ import annotations

import json
import signal
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import interfaces_stack as istack  # noqa: E402
from evals_world import *  # noqa: E402,F403
from evals_world import (  # noqa: E402
    ABL_V1,
    ABL_V2,
    CASES,
    DETERMINISTIC,
    FAST_SUITE,
    ONLINE_DATASET,
    ONLINE_GRADERS,
    SUITE,
    SUITE_REF,
    Cli,
    PySdk,
    TsSdk,
    World,
    grade_all,
    publish_version,
    setup_publisher,
    start_and_wait,
    until,
    wait_final,
)  # fmt: skip


def main() -> int:
    info = json.loads(Path(sys.argv[1]).read_text())
    work = Path(tempfile.mkdtemp(prefix="axis-console-evals-"))
    stack = istack.Stack.from_info(info, work)
    w = World(stack)
    # the people of the browser test: the owner (publisher, run starter), a reviewer, and a viewer
    emails = {
        "owner": w.a["owner_email"],
        "reviewer": w.reviewer["email"],
    }
    w.owner.call("evalsDatasetCreate", body={"name": "answer-cases", "cases": CASES})
    w.owner.call("evalsSuiteCreate", body=SUITE)
    w.owner.call("evalsSuiteCreate", body=FAST_SUITE)
    setup_publisher(w)
    w.start_runner("runner-a")
    time.sleep(2.5)
    v1 = publish_version(w, ABL_V1, local=True)
    run1 = start_and_wait(w, Cli, SUITE_REF, v1)
    until(
        lambda: w.owner.call("evalsRunGet", id=run1["id"])["pending_human"] == 4,
        "v1 human review",
        120,
    )
    grade_all(w, run1["id"], {"q1": 0.9, "q2": 0.9, "q3": 0.9, "q4": 0.9})
    wait_final(w, run1["id"])
    stack.ops("mp/publisher-verify", tenant_id=w.a["tenant_id"])
    stack.ops(
        "mp/review-and-list",
        tenant_id=w.a["tenant_id"],
        namespace=w.ns,
        name="answer-agent",
        version="1.0.0",
    )
    v2 = publish_version(w, ABL_V2, local=True)
    run2 = start_and_wait(w, PySdk, SUITE_REF, v2)
    until(
        lambda: w.owner.call("evalsRunGet", id=run2["id"])["pending_human"] == 4,
        "v2 human review",
        120,
    )
    grade_all(w, run2["id"], {"q1": 0.9, "q2": 0.9, "q3": 0.4, "q4": 0.4})
    wait_final(w, run2["id"])
    # a run left WAITING for a human: the browser reviewer grades it
    run3 = start_and_wait(w, TsSdk, SUITE_REF, v1, mode="manual")
    until(
        lambda: w.owner.call("evalsRunGet", id=run3["id"])["pending_human"] == 4, "pending run", 120
    )
    # hostile output
    w.owner.call(
        "evalsDatasetCreate",
        body={"name": "xss-cases", "cases": [{"id": "x1", "input": "XSS please, claim 1001"}]},
    )
    w.owner.call(
        "evalsSuiteCreate",
        body={
            "ref": "xss-fast@1.0.0",
            "dataset_ref": "xss-cases@1",
            "graders": DETERMINISTIC[1:],
            "pass_threshold": 0.1,
            "required_for_release": False,
        },
    )
    run4 = start_and_wait(w, PySdk, "xss-fast@1.0.0", v1, mode="manual")
    wait_final(w, run4["id"])
    # online samples
    w.owner.call("evalsDatasetCreate", body=ONLINE_DATASET)
    w.owner.call(
        "evalsSuiteCreate",
        body={
            "ref": "online-health@1.0.0",
            "dataset_ref": "online-seed@1",
            "graders": ONLINE_GRADERS,
            "pass_threshold": 0.5,
            "required_for_release": False,
        },
    )
    w.owner.call(
        "evalsSamplingPut",
        id="prod-health",
        body={
            "blueprint": "answer-agent",
            "suite": "online-health@1.0.0",
            "rate": 1.0,
            "max_per_hour": 100,
            "redaction": "always",
        },
    )
    w.start_runner("runner-a", online=True)
    time.sleep(2.0)
    for i in range(3):
        r = w.owner.call(
            "runStart",
            name="answer-agent",
            version="1.0.0",
            input={"prompt": f"answer claim {3000 + i}"},
        )
        w.owner.call("runWait", id=r["id"])
    until(
        lambda: (
            w.owner.call("evalsSamplingSummary", params={"blueprint": "answer-agent"})["items"][0][
                "count"
            ]
            >= 3
        ),
        "online samples",
        120,
    )
    print(json.dumps({
        "tenant_id": w.a["tenant_id"], "org": w.a["org"], "emails": emails, "ns": w.ns,
        "owner_key": w.owner_key, "key_b": w.key_b, "org_b": w.b["org"],
        "v1": v1, "v2": v2, "run1": run1["id"], "run2": run2["id"], "run3": run3["id"], "run4": run4["id"],
        "reviewer_member": w.reviewer["member_id"],
    }), flush=True)  # fmt: skip
    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    try:
        while not stop:
            time.sleep(0.5)
    finally:
        for r in w.runners.values():
            r.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
