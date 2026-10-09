# Load test report (short)

Generated 2026-10-08T19:12:21.673Z. **Machine:** 4 x Intel(R) Xeon(R) Processor @ 2.10GHz, 15.7 GiB RAM, linux 6.18.44-fc-v80 x64, Node v22.22.2. load generator, gateway, kernel, run service, control plane and Postgres all share this one machine.

Latencies are milliseconds from the INTENDED start of each request (open model, coordinated-omission aware); `svc p99` is from the actual send.

| scenario        | rate/s |   ok | errors | achieved/s |    p50 |    p95 |    p99 |  p99.9 |    max | svc p99 | gen lag max |
| --------------- | -----: | ---: | -----: | ---------: | -----: | -----: | -----: | -----: | -----: | ------: | ----------: |
| me              |    300 | 2991 |      0 |      299.1 |   10.8 |   45.6 |   63.5 |   83.8 |  113.7 |    62.7 |    30.67 ms |
| auditList       |     60 |  590 |      0 |         59 |  7.647 |   20.6 |   38.5 |   65.2 |   65.2 |    38.9 |    15.88 ms |
| auditVerify     |      5 |   59 |      0 |        5.9 |  9.519 |   17.5 |   19.6 |   19.6 |   19.6 |    19.6 |     2.17 ms |
| registryResolve |     60 |  590 |      0 |         59 |   11.9 |   26.2 |   36.9 |   44.1 |   44.1 |    35.1 |     4.44 ms |
| runStartAck     |     20 |  206 |      0 |       20.6 |   34.5 |   76.5 |   99.5 |  119.8 |  119.8 |    99.1 |     4.03 ms |
| runComplete     |     10 |   98 |      0 |        9.8 |   81.7 |  130.7 |  148.0 |  148.0 |  148.0 |   148.7 |     2.48 ms |
| gate            |    400 |    0 |   3953 |      394.3 | 5001.2 | 5025.8 | 5218.3 | 5255.2 | 5260.6 |  5156.9 |   259.28 ms |

## Errors

- gate: {"decision_DECISION_DENY":47,"Error":3896,"shed":10}

## NFR checks

| id                      | target                               | measured | verdict          | note                                                                          |
| ----------------------- | ------------------------------------ | -------: | ---------------- | ----------------------------------------------------------------------------- |
| gate.grpc.p99           | gate adds < 25 ms p99 to a tool call |        - | **Not measured** | 400/s, ALLOW with a Postgres audit row per call                               |
| api.me.p99              | control-plane API p99 < 200 ms       | 63.46 ms | **Met**          | 300/s on one small machine; the 1k RPS part of the target is NOT demonstrated |
| api.auditList.p99       | API p99 < 200 ms                     | 38.46 ms | **Met**          |                                                                               |
| api.registryResolve.p99 | API p99 < 200 ms                     |  36.9 ms | **Met**          |                                                                               |
| run.start.p99           | proposed: < 200 ms                   | 99.52 ms | **Met**          |                                                                               |
| audit.verify.100k       | proposed: < 30 s                     |   3.38 s | **Met**          |                                                                               |

## Other measurements

```json
{
  "sseFanOut": [
    {
      "subscribers": 10,
      "error": "Error: no pending approval for the fan-out run"
    },
    {
      "subscribers": 100,
      "connected": 16,
      "completed": 16,
      "eventsPerSubscriberMin": 23,
      "eventsPerSubscriberMax": 23,
      "deliveryMs": {
        "p50": 121.8,
        "p95": 140.6,
        "p99": 140.6,
        "max": 140.6
      },
      "failed": 84
    },
    {
      "subscribers": 500,
      "connected": 16,
      "completed": 16,
      "eventsPerSubscriberMin": 23,
      "eventsPerSubscriberMax": 23,
      "deliveryMs": {
        "p50": 257.6,
        "p95": 275.3,
        "p99": 275.3,
        "max": 275.3
      },
      "failed": 484
    }
  ],
  "auditAppendSingleChain": {
    "events": 5000,
    "concurrency": 1,
    "tenants": 1,
    "appendSeconds": 17.98,
    "appendsPerSec": 278.02,
    "appendLatencyUs": {
      "count": 5000,
      "min": 1238,
      "mean": 3592.07,
      "p50": 2649,
      "p90": 6947,
      "p95": 8035,
      "p99": 12071,
      "p999": 51711,
      "max": 112685
    },
    "errors": {},
    "verifySeconds": 0.11,
    "verifyEventsPerSec": 47095.89,
    "verifyOk": true
  },
  "auditAppendConcurrentSameChain": {
    "events": 5000,
    "concurrency": 8,
    "tenants": 1,
    "appendSeconds": 20.08,
    "appendsPerSec": 249.03,
    "appendLatencyUs": {
      "count": 5000,
      "min": 4569,
      "mean": 32099.02,
      "p50": 28783,
      "p90": 49407,
      "p95": 57471,
      "p99": 71103,
      "p999": 103231,
      "max": 111347
    },
    "errors": {},
    "verifySeconds": 0.11,
    "verifyEventsPerSec": 43954.96,
    "verifyOk": true
  },
  "auditAppendManyChains": {
    "events": 5000,
    "concurrency": 8,
    "tenants": 8,
    "appendSeconds": 9.23,
    "appendsPerSec": 541.96,
    "appendLatencyUs": {
      "count": 5000,
      "min": 1775,
      "mean": 14750.92,
      "p50": 11223,
      "p90": 28591,
      "p95": 37279,
      "p99": 55135,
      "p999": 88703,
      "max": 132305
    },
    "errors": {},
    "verifySeconds": 0.18,
    "verifyEventsPerSec": 27345.35,
    "verifyOk": true
  },
  "auditVerify": {
    "events": 100000,
    "seedSeconds": 14.51,
    "verifySeconds": 3.38,
    "verifyOk": true,
    "verifySecondsPer100k": 3.38
  },
  "k6": [
    {
      "script": "gateway.js",
      "status": "ran",
      "exitCode": 99,
      "version": "k6 v0.54.0 (commit/baba871c8a, go1.23.1, linux/amd64)",
      "metrics": {
        "http_req_tls_handshaking": {
          "p(95)": 0,
          "avg": 0,
          "min": 0,
          "med": 0,
          "max": 0,
          "p(90)": 0
        },
        "http_req_duration{scenario:auth_me}": {
          "avg": 1485.294545221813,
          "min": 155.439218,
          "med": 1562.671434,
          "max": 2094.390545,
          "p(90)": 1978.0045684,
          "p(95)": 2010.3169392,
          "thresholds": {
            "p(99)<200": true
          }
        },
        "http_req_connecting": {
          "p(95)": 0.1712479499999999,
          "avg": 0.10220047391304345,
          "min": 0,
          "med": 0,
          "max": 22.199789,
          "p(90)": 0.13605130000000001
        },
        "dropped_iterations": {
          "count": 154,
          "rate": 8.456722294998372
        },
        "iteration_duration": {
          "p(95)": 2956.0952311,
          "avg": 1701.6592438400992,
          "min": 156.075556,
          "med": 1617.932299,
          "max": 9521.576028,
          "p(90)": 2405.1231766
        },
        "data_received": {
          "count": 14496566,
          "rate": 796061.2525526971
        },
        "iterations": {
          "rate": 113.67152695225083,
          "count": 2070
        },
        "http_req_receiving": {
          "p(90)": 0.22013040000000006,
          "p(95)": 0.3540800999999999,
          "avg": 0.14455167971014474,
          "min": 0.016894,
          "med": 0.0849255,
          "max": 12.423835
        },
        "http_req_duration": {
          "avg": 1701.244160883575,
          "min": 155.439218,
          "med": 1617.386842,
          "max": 9520.804348,
          "p(90)": 2404.9133617,
          "p(95)": 2955.71705825
        },
        "http_reqs": {
          "count": 2070,
          "rate": 113.67152695225083
        },
        "http_req_sending": {
          "p(90)": 0.08232010000000001,
          "p(95)": 0.12031149999999999,
          "avg": 0.04809981835748784,
          "min": 0.00486,
          "med": 0.021383,
          "max": 10.647836
        },
        "vus": {
          "value": 8,
          "min": 8,
          "max": 311
        },
        "checks": {
          "passes": 2070,
          "fails": 0,
          "value": 1
        },
        "data_sent": {
          "count": 459727,
          "rate": 25245.347860472182
        },
        "http_req_blocked": {
          "p(90)": 0.21885040000000022,
          "p(95)": 0.31550169999999994,
          "avg": 0.1327856425120773,
          "min": 0.001889,
          "med": 0.007232,
          "max": 22.332907
        },
        "http_req_duration{scenario:registry_resolve}": {
          "med": 2644.073279,
          "max": 3353.943253,
          "p(90)": 3119.265672,
          "p(95)": 3207.2355079999998,
          "avg": 2445.9743936975947,
          "min": 638.384999,
          "thresholds": {
            "p(99)<200": true
          }
        },
        "http_req_failed": {
          "passes": 0,
          "fails": 2070,
          "thresholds": {
            "rate<0.01": false
          },
          "value": 0
        },
        "http_req_duration{scenario:audit_list}": {
          "max": 2070.284362,
          "p(90)": 1973.9647226000002,
          "p(95)": 2015.7226137,
          "avg": 1477.361033796666,
          "min": 332.526495,
          "med": 1551.9841615,
          "thresholds": {
            "p(99)<200": true
          }
        },
        "http_req_duration{expected_response:true}": {
          "p(90)": 2404.9133617,
          "p(95)": 2955.71705825,
          "avg": 1701.244160883575,
          "min": 155.439218,
          "med": 1617.386842,
          "max": 9520.804348
        },
        "http_req_waiting": {
          "avg": 1701.0515093855108,
          "min": 155.202158,
          "med": 1617.2524485,
          "max": 9520.635673,
          "p(90)": 2404.6946293,
          "p(95)": 2955.61086255
        },
        "http_req_duration{scenario:run_start}": {
          "med": 1606.047932,
          "max": 2089.113962,
          "p(90)": 2013.236355,
          "p(95)": 2050.8928255,
          "avg": 1523.898073395605,
          "min": 456.625573,
          "thresholds": {
            "p(99)<200": true
          }
        },
        "vus_max": {
          "max": 400,
          "value": 400,
          "min": 254
        }
      },
      "reason": "time=\"2026-10-08T19:12:21Z\" level=error msg=\"thresholds on metrics 'http_req_duration{scenario:audit_list}, http_req_duration{scenario:auth_me}, http_req_duration{scenario:registry_resolve}, http_req_duration{scenario:run_start}' have been crossed\"\n"
    },
    {
      "script": "gate-grpc.js",
      "status": "ran",
      "exitCode": 107,
      "version": "k6 v0.54.0 (commit/baba871c8a, go1.23.1, linux/amd64)",
      "reason": "time=\"2026-10-08T19:12:21Z\" level=error msg=\"GoError: stat /home/user/AgenticOS/.claude/worktrees/p9-resilience/perf/k6/proto/axis/runtime/v1/gate.proto: no such file or directory\\n\\tat reflect.methodValueCall (native)\\n\\tat file:///home/user/AgenticOS/.claude/worktrees/p9-resilience/perf/k6/gate-grpc.js:7:12(23)\\n\" hint=\"script exception\"\n"
    }
  ]
}
```
