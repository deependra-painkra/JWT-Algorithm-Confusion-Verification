{
  "target": "https://httpbin.org/get",
  "results": [
    {
      "test": "valid_rs256",
      "status": 200,
      "sensitive": false,
      "result": "PASS",
      "time": "2026-03-20T05:42:13.466282+00:00"
    },
    {
      "test": "alg_none",
      "status": 200,
      "sensitive": false,
      "result": "FAIL",
      "time": "2026-03-20T05:42:15.327723+00:00"
    },
    {
      "test": "hs256_pubkey",
      "error": "The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC secret.",
      "result": "ERROR"
    },
    {
      "test": "tamper_admin",
      "error": "The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC secret.",
      "result": "ERROR"
    },
    {
      "test": "expired",
      "status": 200,
      "sensitive": false,
      "result": "FAIL",
      "time": "2026-03-20T05:42:17.355626+00:00"
    }
  ]
}