# Load test report (short)

Generated 2026-10-09T22:46:10.182Z. **Machine:** 4 x Intel(R) Xeon(R) Processor @ 2.10GHz, 15.7 GiB RAM, linux 6.18.44-fc-v80 x64, Node v22.22.2. load generator, gateway, kernel, run service, control plane and Postgres all share this one machine.

Latencies are milliseconds from the INTENDED start of each request (open model, coordinated-omission aware); `svc p99` is from the actual send.

| scenario | rate/s | ok | errors | achieved/s | p50 | p95 | p99 | p99.9 | max | svc p99 | gen lag max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| me | 300 | 2991 | 0 | 299.1 | 3.763 | 10.7 | 25.2 | 66.6 | 70.7 | 23.6 | 8.23 ms |
| auditList | 60 | 590 | 0 | 59 | 3.569 | 5.483 | 7.007 | 18.0 | 18.0 | 7.887 | 1.3 ms |
| auditVerify | 5 | 59 | 0 | 5.9 | 6.655 | 11.1 | 21.3 | 21.3 | 21.3 | 21.9 | 1.42 ms |
| registryResolve | 60 | 590 | 0 | 59 | 6.807 | 13.7 | 43.5 | 51.9 | 51.9 | 22.6 | 36.23 ms |
| runStartAck | 20 | 206 | 0 | 20.6 | 21.8 | 40.8 | 49.6 | 58.6 | 58.6 | 50.5 | 2.15 ms |
| runComplete | 10 | 98 | 0 | 9.8 | 58.6 | 81.2 | 119.4 | 119.4 | 119.4 | 119.8 | 5.68 ms |
| gate | 400 | 3953 | 0 | 395.3 | 1953.8 | 2353.2 | 2377.7 | 2388.0 | 2388.5 | 2377.7 | 10.75 ms |

## NFR checks

| id | target | measured | verdict | note |
| --- | --- | ---: | --- | --- |
| gate.grpc.p99 | gate adds < 25 ms p99 to a tool call | 2377.73 ms | **Not met** | 400/s, ALLOW with a Postgres audit row per call |
| api.me.p99 | control-plane API p99 < 200 ms | 25.23 ms | **Met** | 300/s on one small machine; the 1k RPS part of the target is NOT demonstrated |
| api.auditList.p99 | API p99 < 200 ms | 7.01 ms | **Met** |  |
| api.registryResolve.p99 | API p99 < 200 ms | 43.52 ms | **Met** |  |
| run.start.p99 | proposed: < 200 ms | 49.63 ms | **Met** |  |
| audit.verify.100k | proposed: < 30 s | 1.94 s | **Met** |  |

## Other measurements

```json
{
  "sseFanOut": [
    {
      "subscribers": 10,
      "connected": 10,
      "completed": 10,
      "eventsPerSubscriberMin": 24,
      "eventsPerSubscriberMax": 24,
      "deliveryMs": {
        "p50": 54.4,
        "p95": 87.2,
        "p99": 87.2,
        "max": 87.2
      },
      "failed": 0
    },
    {
      "subscribers": 100,
      "connected": 16,
      "completed": 16,
      "eventsPerSubscriberMin": 24,
      "eventsPerSubscriberMax": 24,
      "deliveryMs": {
        "p50": 81.3,
        "p95": 93.7,
        "p99": 93.7,
        "max": 93.7
      },
      "failed": 84
    },
    {
      "subscribers": 500,
      "connected": 16,
      "completed": 16,
      "eventsPerSubscriberMin": 24,
      "eventsPerSubscriberMax": 24,
      "deliveryMs": {
        "p50": 68.7,
        "p95": 104.6,
        "p99": 104.6,
        "max": 104.6
      },
      "failed": 484
    }
  ],
  "auditAppendSingleChain": {
    "events": 5000,
    "concurrency": 1,
    "tenants": 1,
    "appendSeconds": 12.32,
    "appendsPerSec": 405.73,
    "appendLatencyUs": {
      "count": 5000,
      "min": 1225,
      "mean": 2462.05,
      "p50": 2011,
      "p90": 3113,
      "p95": 3775,
      "p99": 7091,
      "p999": 67839,
      "max": 149219
    },
    "errors": {},
    "verifySeconds": 0.14,
    "verifyEventsPerSec": 36213.6,
    "verifyOk": true
  },
  "auditAppendConcurrentSameChain": {
    "events": 5000,
    "concurrency": 8,
    "tenants": 1,
    "appendSeconds": 12.15,
    "appendsPerSec": 411.38,
    "appendLatencyUs": {
      "count": 5000,
      "min": 11289,
      "mean": 19428.9,
      "p50": 18527,
      "p90": 24495,
      "p95": 27519,
      "p99": 39199,
      "p999": 64991,
      "max": 70020
    },
    "errors": {},
    "verifySeconds": 0.11,
    "verifyEventsPerSec": 46357.49,
    "verifyOk": true
  },
  "auditAppendManyChains": {
    "events": 5000,
    "concurrency": 8,
    "tenants": 8,
    "appendSeconds": 3.88,
    "appendsPerSec": 1289.18,
    "appendLatencyUs": {
      "count": 5000,
      "min": 1439,
      "mean": 6200.55,
      "p50": 5363,
      "p90": 10639,
      "p95": 12775,
      "p99": 17791,
      "p999": 25343,
      "max": 28692
    },
    "errors": {},
    "verifySeconds": 0.1,
    "verifyEventsPerSec": 48173.93,
    "verifyOk": true
  },
  "auditVerify": {
    "events": 100000,
    "seedSeconds": 13.32,
    "verifySeconds": 1.94,
    "verifyOk": true,
    "verifySecondsPer100k": 1.94
  },
  "k6": [
    {
      "script": "gateway.js",
      "status": "ran",
      "exitCode": 99,
      "version": "k6 v0.54.0 (commit/baba871c8a, go1.23.1, linux/amd64)",
      "metrics": {
        "http_req_duration{scenario:auth_me}": {
          "avg": 80.51032167533359,
          "min": 2.339442,
          "med": 31.115133999999998,
          "max": 367.534868,
          "p(90)": 234.9626303000001,
          "p(95)": 303.0214372,
          "thresholds": {
            "p(99)<200": true
          }
        },
        "http_req_duration{expected_response:true}": {
          "avg": 94.51267678587503,
          "min": 2.339442,
          "med": 35.050909,
          "max": 1571.717012,
          "p(90)": 284.48932379999997,
          "p(95)": 326.4827939
        },
        "vus": {
          "max": 54,
          "value": 3,
          "min": 0
        },
        "http_req_waiting": {
          "max": 1571.547476,
          "p(90)": 284.3209912,
          "p(95)": 326.06872760000005,
          "avg": 94.30769887854247,
          "min": 2.263816,
          "med": 34.944553
        },
        "http_req_connecting": {
          "p(95)": 0.16279510000000008,
          "avg": 0.05480028250112459,
          "min": 0,
          "med": 0,
          "max": 13.97361,
          "p(90)": 0.09424979999999994
        },
        "http_req_duration": {
          "p(90)": 284.48932379999997,
          "p(95)": 326.4827939,
          "avg": 94.51267678587503,
          "min": 2.339442,
          "med": 35.050909,
          "max": 1571.717012
        },
        "http_req_failed": {
          "passes": 0,
          "fails": 2223,
          "thresholds": {
            "rate<0.01": false
          },
          "value": 0
        },
        "http_req_sending": {
          "avg": 0.04910213225371121,
          "min": 0.005787,
          "med": 0.022867,
          "max": 3.421313,
          "p(90)": 0.08402859999999998,
          "p(95)": 0.13417860000000006
        },
        "http_reqs": {
          "rate": 147.92616638833454,
          "count": 2223
        },
        "http_req_blocked": {
          "min": 0.002359,
          "med": 0.00656,
          "max": 14.077061,
          "p(90)": 0.17384999999999995,
          "p(95)": 0.29446380000000005,
          "avg": 0.08006148987854263
        },
        "http_req_receiving": {
          "p(95)": 0.4658987000000003,
          "avg": 0.15587577507872225,
          "min": 0.016458,
          "med": 0.074834,
          "max": 6.990182,
          "p(90)": 0.2599635999999999
        },
        "data_received": {
          "rate": 977216.1590541705,
          "count": 14685377
        },
        "iterations": {
          "count": 2223,
          "rate": 147.92616638833454
        },
        "checks": {
          "fails": 0,
          "passes": 2223,
          "value": 1
        },
        "http_req_duration{scenario:run_start}": {
          "min": 15.312457,
          "med": 39.069888,
          "max": 390.968654,
          "p(90)": 278.315818,
          "p(95)": 351.852487,
          "avg": 105.97681739560441,
          "thresholds": {
            "p(99)<200": true
          }
        },
        "http_req_duration{scenario:audit_list}": {
          "p(95)": 305.32589,
          "avg": 83.6776163887043,
          "min": 5.868295,
          "med": 32.116063,
          "max": 371.406469,
          "p(90)": 244.119683,
          "thresholds": {
            "p(99)<200": true
          }
        },
        "http_req_duration{scenario:registry_resolve}": {
          "avg": 134.68003728571438,
          "min": 5.181297,
          "med": 54.147521,
          "max": 573.070199,
          "p(90)": 396.809639,
          "p(95)": 519.875219,
          "thresholds": {
            "p(99)<200": true
          }
        },
        "http_req_tls_handshaking": {
          "max": 0,
          "p(90)": 0,
          "p(95)": 0,
          "avg": 0,
          "min": 0,
          "med": 0
        },
        "data_sent": {
          "count": 491812,
          "rate": 32726.88427520449
        },
        "iteration_duration": {
          "avg": 94.90795063382829,
          "min": 2.486163,
          "med": 35.389288,
          "max": 1572.570276,
          "p(90)": 284.792353,
          "p(95)": 327.041244
        },
        "vus_max": {
          "value": 250,
          "min": 250,
          "max": 250
        }
      },
      "reason": "time=\"2026-10-09T22:46:10Z\" level=error msg=\"thresholds on metrics 'http_req_duration{scenario:audit_list}, http_req_duration{scenario:auth_me}, http_req_duration{scenario:registry_resolve}, http_req_duration{scenario:run_start}' have been crossed\"\n"
    },
    {
      "script": "gate-grpc.js",
      "status": "ran",
      "exitCode": 107,
      "version": "k6 v0.54.0 (commit/baba871c8a, go1.23.1, linux/amd64)",
      "reason": "time=\"2026-10-09T22:46:10Z\" level=error msg=\"GoError: stat /home/user/AgenticOS/.claude/worktrees/p9-resilience/perf/k6/proto/axis/runtime/v1/gate.proto: no such file or directory\\n\\tat reflect.methodValueCall (native)\\n\\tat file:///home/user/AgenticOS/.claude/worktrees/p9-resilience/perf/k6/gate-grpc.js:7:12(23)\\n\" hint=\"script exception\"\n"
    }
  ]
}
```
