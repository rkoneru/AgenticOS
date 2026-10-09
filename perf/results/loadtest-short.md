# Load test report (short)

Generated 2026-10-09T22:59:00.064Z. **Machine:** 4 x Intel(R) Xeon(R) Processor @ 2.10GHz, 15.7 GiB RAM, linux 6.18.44-fc-v80 x64, Node v22.22.2. load generator, gateway, kernel, run service, control plane and Postgres all share this one machine.

Latencies are milliseconds from the INTENDED start of each request (open model, coordinated-omission aware); `svc p99` is from the actual send.

| scenario | rate/s | ok | errors | achieved/s | p50 | p95 | p99 | p99.9 | max | svc p99 | gen lag max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| me | 300 | 2991 | 0 | 299.1 | 3.399 | 8.111 | 14.2 | 28.7 | 32.6 | 13.1 | 7.69 ms |
| auditList | 60 | 590 | 0 | 59 | 3.773 | 6.515 | 18.9 | 82.0 | 82.0 | 18.9 | 3.3 ms |
| auditVerify | 5 | 59 | 0 | 5.9 | 7.131 | 11.1 | 11.6 | 11.6 | 11.6 | 12.0 | 0.61 ms |
| registryResolve | 60 | 590 | 0 | 59 | 6.571 | 11.9 | 19.0 | 91.6 | 91.6 | 19.5 | 39.4 ms |
| runStartAck | 20 | 206 | 0 | 20.6 | 17.7 | 37.4 | 53.2 | 57.9 | 57.9 | 53.3 | 0.87 ms |
| runComplete | 10 | 98 | 0 | 9.8 | 53.4 | 66.2 | 108.1 | 108.1 | 108.1 | 107.6 | 0.98 ms |
| gate@50 | 50 | 482 | 0 | 48.2 | 4.791 | 8.327 | 11.9 | 18.3 | 18.3 | 12.0 | 0.98 ms |
| gate@100 | 100 | 981 | 0 | 98.1 | 4.711 | 11.9 | 36.1 | 48.8 | 48.8 | 28.1 | 34.45 ms |
| gate@200 | 200 | 1976 | 0 | 197.6 | 7.535 | 34.0 | 56.2 | 65.7 | 70.0 | 56.1 | 8.57 ms |
| gate@400 | 400 | 3953 | 0 | 395.3 | 819.7 | 1002.0 | 1018.4 | 1026.6 | 1027.0 | 1018.9 | 10.03 ms |

## NFR checks

| id | target | measured | verdict | note |
| --- | --- | ---: | --- | --- |
| gate.grpc.p99 | gate adds < 25 ms p99 to a tool call | 11.86 ms | **Met** | at 50/s, ALLOW + Postgres audit row per call, one tenant; sweep: 50/s p99 11.86 ms, 100/s p99 36.13 ms, 200/s p99 56.16 ms, 400/s p99 1018.37 ms |
| api.me.p99 | control-plane API p99 < 200 ms | 14.22 ms | **Met** | 300/s on one small machine; the 1k RPS part of the target is NOT demonstrated |
| api.auditList.p99 | API p99 < 200 ms | 18.86 ms | **Met** |  |
| api.registryResolve.p99 | API p99 < 200 ms | 19.02 ms | **Met** |  |
| run.start.p99 | proposed: < 200 ms | 53.22 ms | **Met** |  |
| audit.verify.100k | proposed: < 30 s | 1.78 s | **Met** |  |

## Other measurements

```json
{
  "killSwitchPropagationMs": {
    "samples": 20,
    "p50": 3.931669999990845,
    "max": 15.463410999975167,
    "scope": "one kernel instance; multi-instance propagation (Redis) is NOT built"
  },
  "sseFanOut": [
    {
      "subscribers": 10,
      "connected": 10,
      "completed": 10,
      "eventsPerSubscriberMin": 24,
      "eventsPerSubscriberMax": 24,
      "deliveryMs": {
        "p50": 103.9,
        "p95": 107.5,
        "p99": 107.5,
        "max": 107.5
      },
      "failed": 0
    },
    {
      "subscribers": 100,
      "connected": 100,
      "completed": 100,
      "eventsPerSubscriberMin": 24,
      "eventsPerSubscriberMax": 24,
      "deliveryMs": {
        "p50": 385.2,
        "p95": 451.6,
        "p99": 455.3,
        "max": 455.3
      },
      "failed": 0
    },
    {
      "subscribers": 500,
      "connected": 500,
      "completed": 500,
      "eventsPerSubscriberMin": 24,
      "eventsPerSubscriberMax": 24,
      "deliveryMs": {
        "p50": 2383.1,
        "p95": 2710.5,
        "p99": 2735.5,
        "max": 2741.1
      },
      "failed": 0
    }
  ],
  "auditAppendSingleChain": {
    "events": 5000,
    "concurrency": 1,
    "tenants": 1,
    "appendSeconds": 11.91,
    "appendsPerSec": 419.86,
    "appendLatencyUs": {
      "count": 5000,
      "min": 1283,
      "mean": 2378.61,
      "p50": 2107,
      "p90": 3279,
      "p95": 4021,
      "p99": 6363,
      "p999": 11559,
      "max": 41049
    },
    "errors": {},
    "verifySeconds": 0.12,
    "verifyEventsPerSec": 41906.5,
    "verifyOk": true
  },
  "auditAppendConcurrentSameChain": {
    "events": 5000,
    "concurrency": 8,
    "tenants": 1,
    "appendSeconds": 11.07,
    "appendsPerSec": 451.85,
    "appendLatencyUs": {
      "count": 5000,
      "min": 10931,
      "mean": 17688.46,
      "p50": 16863,
      "p90": 22127,
      "p95": 25327,
      "p99": 33471,
      "p999": 42623,
      "max": 60322
    },
    "errors": {},
    "verifySeconds": 0.12,
    "verifyEventsPerSec": 42334.94,
    "verifyOk": true
  },
  "auditAppendManyChains": {
    "events": 5000,
    "concurrency": 8,
    "tenants": 8,
    "appendSeconds": 2.83,
    "appendsPerSec": 1766.8,
    "appendLatencyUs": {
      "count": 5000,
      "min": 1413,
      "mean": 4521.68,
      "p50": 3841,
      "p90": 7467,
      "p95": 9031,
      "p99": 12567,
      "p999": 27823,
      "max": 35072
    },
    "errors": {},
    "verifySeconds": 0.11,
    "verifyEventsPerSec": 44665.76,
    "verifyOk": true
  },
  "auditVerify": {
    "events": 100000,
    "seedSeconds": 12.55,
    "verifySeconds": 1.78,
    "verifyOk": true,
    "verifySecondsPer100k": 1.78
  },
  "k6": [
    {
      "script": "gateway.js",
      "status": "ran",
      "exitCode": 0,
      "version": "k6 v0.54.0 (commit/baba871c8a, go1.23.1, linux/amd64)",
      "metrics": {
        "http_req_duration{scenario:audit_list}": {
          "avg": 28.750091913333332,
          "med": 22.772494000000002,
          "p(95)": 73.25067380000003,
          "p(99)": 101.78660049999998,
          "max": 116.98029,
          "thresholds": {
            "p(99)<200": false
          }
        },
        "http_req_duration{scenario:auth_me}": {
          "avg": 27.14464169666672,
          "med": 24.6912725,
          "p(95)": 70.90656754999998,
          "p(99)": 103.27397599000001,
          "max": 115.165646,
          "thresholds": {
            "p(99)<200": false
          }
        },
        "http_req_duration{expected_response:true}": {
          "avg": 34.68662340477261,
          "med": 27.294534,
          "p(95)": 91.273442,
          "p(99)": 296.1026504000006,
          "max": 694.494858
        },
        "http_req_blocked": {
          "avg": 0.0577690886987844,
          "med": 0.006433,
          "p(95)": 0.234738,
          "p(99)": 0.5453648000000009,
          "max": 10.565419
        },
        "http_req_duration{scenario:registry_resolve}": {
          "avg": 45.240526916666646,
          "med": 39.7409715,
          "p(95)": 110.92701045000005,
          "p(99)": 171.74993183999993,
          "max": 192.506838,
          "thresholds": {
            "p(99)<200": false
          }
        },
        "http_req_sending": {
          "avg": 0.034887220621341725,
          "med": 0.024296,
          "p(95)": 0.078348,
          "p(99)": 0.18986180000000114,
          "max": 3.241703
        },
        "data_sent": {
          "count": 491323,
          "rate": 32714.808103869258
        },
        "http_req_duration": {
          "p(95)": 91.273442,
          "p(99)": 296.1026504000006,
          "max": 694.494858,
          "avg": 34.68662340477261,
          "med": 27.294534
        },
        "http_req_failed": {
          "passes": 0,
          "fails": 2221,
          "thresholds": {
            "rate<0.01": false
          },
          "value": 0
        },
        "http_req_tls_handshaking": {
          "avg": 0,
          "med": 0,
          "p(95)": 0,
          "p(99)": 0,
          "max": 0
        },
        "iteration_duration": {
          "p(95)": 92.027535,
          "p(99)": 297.33235880000075,
          "max": 696.67144,
          "avg": 34.94881453264296,
          "med": 27.573432
        },
        "iterations": {
          "count": 2221,
          "rate": 147.88558402251394
        },
        "checks": {
          "fails": 0,
          "passes": 2221,
          "value": 1
        },
        "vus": {
          "value": 0,
          "min": 0,
          "max": 3
        },
        "http_reqs": {
          "count": 2221,
          "rate": 147.88558402251394
        },
        "http_req_waiting": {
          "avg": 34.56055272805045,
          "med": 27.137046,
          "p(95)": 91.196814,
          "p(99)": 295.98554700000057,
          "max": 694.189229
        },
        "http_req_receiving": {
          "p(99)": 0.48588980000000503,
          "max": 1.993352,
          "avg": 0.0911834561008553,
          "med": 0.069925,
          "p(95)": 0.175728
        },
        "http_req_duration{scenario:run_start}": {
          "avg": 46.48166414285717,
          "med": 34.985533,
          "p(95)": 102.412095,
          "p(99)": 153.56277249999997,
          "max": 157.190632,
          "thresholds": {
            "p(99)<200": false
          }
        },
        "http_req_connecting": {
          "max": 10.481733,
          "avg": 0.04146569653309318,
          "med": 0,
          "p(95)": 0.152842,
          "p(99)": 0.34837880000000016
        },
        "vus_max": {
          "value": 250,
          "min": 250,
          "max": 250
        },
        "data_received": {
          "rate": 974881.8785870716,
          "count": 14641134
        }
      }
    },
    {
      "script": "gate-grpc.js",
      "status": "ran",
      "exitCode": 99,
      "version": "k6 v0.54.0 (commit/baba871c8a, go1.23.1, linux/amd64)",
      "metrics": {
        "checks": {
          "fails": 0,
          "passes": 6000,
          "thresholds": {
            "rate>0.999": false
          },
          "value": 1
        },
        "grpc_req_duration": {
          "avg": 4.5394271463333355,
          "med": 3.5253550000000002,
          "p(95)": 6.25794355,
          "p(99)": 43.657111399999756,
          "max": 85.440422,
          "thresholds": {
            "p(99)<25": true
          }
        },
        "data_sent": {
          "count": 1078287,
          "rate": 71879.65203273013
        },
        "data_received": {
          "count": 836218,
          "rate": 55743.098881379
        },
        "iteration_duration": {
          "p(99)": 44.6057739699995,
          "max": 86.924417,
          "avg": 4.938360440000001,
          "med": 3.8731265,
          "p(95)": 6.777267049999992
        },
        "iterations": {
          "count": 3000,
          "rate": 199.98289518299893
        },
        "vus": {
          "value": 1,
          "min": 0,
          "max": 1
        },
        "vus_max": {
          "value": 50,
          "min": 50,
          "max": 50
        }
      },
      "reason": "time=\"2026-10-09T22:59:00Z\" level=error msg=\"thresholds on metrics 'grpc_req_duration' have been crossed\"\n"
    }
  ]
}
```
