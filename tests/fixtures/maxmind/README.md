# MaxMind DB test fixture

`GeoIP2-Country-Test.mmdb.b64` is the Base64 encoding of MaxMind's generated
`test-data/GeoIP2-Country-Test.mmdb` fixture at commit
[`8caf400e4c7e0d58061f4d89d010e1c6b57fac2c`](https://github.com/maxmind/MaxMind-DB/commit/8caf400e4c7e0d58061f4d89d010e1c6b57fac2c).
The upstream repository contains the generator and source records used to
produce it. Tests decode the fixture into a temporary node-local file and
derive wrong-product and partially corrupt cases in hosted CI.

Decoded fixture SHA-256:
`b37601903448683d241af52893c8cbf0fed461e0cdebe0bfaca01891fdeb6db9`.

Copyright (c) 2013-2026 MaxMind, Inc. Licensed under the Apache License 2.0 or
MIT License, matching the upstream `maxmind/MaxMind-DB` repository.
