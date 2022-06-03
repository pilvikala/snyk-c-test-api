# Snyk C/C++ Test using Snyk Test API

This is a proof of concept using experimental Snyk Test API for C and C++ packages. The purpose of this project is to validate our assumptions about package identifications and gather feedback before commiting to a stable API.

WARNING: The API is experimental and will change!

## Getting started

Set `SNYK_TOKEN` environment variable to contain your Snyk API token. To learn how to get the token, see https://docs.snyk.io/features/snyk-api-info/authentication-for-api.

## Example scripts

Tests a single library (curl) and prints out a json:

```shell
PYTHONPATH=src python examples/curl.py
```

Tests a CycloneDX SBOM and lists issues for all known packages:

```shell
PYTHONPATH=src python3 examples/cyclonedx.py examples/cyclonedx-bom.json
```

## How the API works

The experimental test API endpoint is based on Snyk test API for npm packages: https://snyk.docs.apiary.io/#reference/test/npm but there are a few differences:

The API endpoint is at `https://us-east1-snyk-main.cloudfunctions.net/test-cpp`.

The path to test the C or C++ package is `https://us-east1-snyk-main.cloudfunctions.net/test-cpp/<package_coordinate>/<version>?org=<org id>`. To test the endpoint with curl, run:

```shell
curl --header "Authorization: token YOUR_TOKEN" https://us-east1-snyk-main.cloudfunctions.net/test-cpp/cryptopp/1.1.0
```

The API returns a JSON string:

```json
[
  {
    "ok": false,
    "issues": {
      "vulnerabilities": [
        {
          "id": "SNYK-UNMANAGED-CRYPTOPP-2317801",
          "url": "https://snyk.io/vuln/SNYK-UNMANAGED-CRYPTOPP-2317801",
          "title": "Improper Input Validation",
          "type": "vuln",
          "description": "## Overview\n\nAffected versions of this package are vulnerable to Improper Input Validation. Crypto++ (aka cryptopp and libcrypto++) 5.6.4 contained a bug in its ASN.1 BER decoding routine. The library will allocate a memory block based on the length field of the ASN.1 object. If there is not enough content octets in the ASN.1 object, then the function will fail and the memory block will be zeroed even if its unused. There is a noticeable delay during the wipe for a large allocation.\n## Remediation\nThere is no fixed version for `cryptopp`.\n## References\n- [Debian.org](http://www.debian.org/security/2016/dsa-3748)\n- [OSS Security Advisory](http://www.openwall.com/lists/oss-security/2016/12/12/7)\n- [Security Focus](http://www.securityfocus.com/bid/94854)\n",
          "functions": [],
          "package": "cryptopp",
          "severity": "high",
          "exploitMaturity": "no-known-exploit",
          "language": "cpp",
          "packageManager": "unmanaged",
          "semver": {
            "vulnerable": [
              "[,5.6.4]"
            ]
          },
          "publicationTime": "2021-12-14T14:55:04.952856Z",
          "disclosureTime": "2017-01-30T21:59:00Z",
          "identifiers": {
            "CVE": [
              "CVE-2016-9939"
            ],
            "CWE": [
              "CWE-20"
            ]
          },
          "credit": [
            "Unknown"
          ],
          "CVSSv3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
          "cvssScore": 7.5,
          "patches": []
        },
      ],
      "licenses": []
    },
    "packageManager": "unmanaged",
    "licensesPolicy": {
      "severities": {
        "AGPL-1.0": "high",
        "Artistic-1.0": "medium",
        "Artistic-2.0": "medium",
        "CDDL-1.0": "medium",
        "CPOL-1.02": "high",
        "EPL-1.0": "medium",
        "GPL-3.0": "high",
        "MPL-1.1": "medium",
        "MPL-2.0": "medium",
        "MS-RL": "medium",
        "SimPL-2.0": "high",
        "LGPL-3.0": "low",
        "LGPL-2.1": "low",
        "GPL-2.0": "high",
        "LGPL-2.0": "medium",
        "AGPL-3.0": "high",
        "AGPL-3.0-only": "high"
      }
    },
    "org": {
      "name": "michal.brutvan-8fo",
      "id": "4375eaee-5784-404b-805a-b82187f6f61e"
    },
    "dependencyCount": 1
  }
]
```

### Package name matching

In the C/C++ world, there is no single authoritative index we could use for unique matching. Our database of open source packages is curated by a team of analysts that link together projects and their artifacts. The API attempts to simplify this by searching for a package name in our list of internally unique coordinates that map to vulnerabilities.
For each package matching the provided name, a different set of vulnerabilities will be provided. Here's an example of the json output for a package named `openfortivpn`. Note the different set of vulnerabilities and the package names (`openfortivpn` vs `adrienverge/openfortivpn`):

```json
[
  {
    "ok": false,
    "issues": {
      "vulnerabilities": [
        {
          "id": "SNYK-UNMANAGED-OPENFORTIVPN-2327103",
          "url": "https://snyk.io/vuln/SNYK-UNMANAGED-OPENFORTIVPN-2327103",
          "title": "Uninitialized Memory Exposure",
          "type": "vuln",
          "description": "## Overview\n[openfortivpn](https://github.com/adrienverge/openfortivpn) is a client for PPP+SSL VPN tunnel services. It spawns a pppd process and operates the communication between the gateway and this process.\r\n\r\nIt is compatible with Fortinet VPNs.\n\nAffected versions of this package are vulnerable to Uninitialized Memory Exposure. An issue was discovered in openfortivpn 1.11.0 when used with OpenSSL 1.0.2 or later. tunnel.c mishandles certificate validation because the hostname check operates on uninitialized memory. The outcome is that a valid certificate is never accepted (only a malformed certificate may be accepted).\n## Remediation\nUpgrade `openfortivpn` to version 1.12.0 or higher.\n## References\n- [GitHub Commit](https://github.com/adrienverge/openfortivpn/commit/9eee997d599a89492281fc7ffdd79d88cd61afc3)\n- [GitHub Commit](https://github.com/adrienverge/openfortivpn/commit/cd9368c6a1b4ef91d77bb3fdbe2e5bc34aa6f4c4)\n- [GitHub Issue](https://github.com/adrienverge/openfortivpn/issues/536)\n- [Security Advisory](https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/LXVMOLZGPWSU3PQQHJUNYFPGEJQQUENK/)\n",
          "functions": [],
          "package": "openfortivpn",
          "severity": "medium",
          "exploitMaturity": "no-known-exploit",
          "language": "cpp",
          "packageManager": "unmanaged",
          "semver": {
            "vulnerable": [
              "[,1.12.0)"
            ]
          },
          "publicationTime": "2021-12-14T14:55:52Z",
          "disclosureTime": "2020-02-27T18:15:00Z",
          "identifiers": {
            "CVE": [
              "CVE-2020-7042"
            ],
            "CWE": [
              "CWE-201"
            ]
          },
          "credit": [
            "Unknown"
          ],
          "CVSSv3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
          "cvssScore": 5.3,
          "patches": []
        },
        {
          "id": "SNYK-UNMANAGED-OPENFORTIVPN-2327102",
          "url": "https://snyk.io/vuln/SNYK-UNMANAGED-OPENFORTIVPN-2327102",
          "title": "Uninitialized Memory Exposure",
          "type": "vuln",
          "description": "## Overview\n[openfortivpn](https://github.com/adrienverge/openfortivpn) is a client for PPP+SSL VPN tunnel services. It spawns a pppd process and operates the communication between the gateway and this process.\r\n\r\nIt is compatible with Fortinet VPNs.\n\nAffected versions of this package are vulnerable to Uninitialized Memory Exposure. An issue was discovered in openfortivpn 1.11.0 when used with OpenSSL 1.0.2 or later. tunnel.c mishandles certificate validation because an X509_check_host negative error code is interpreted as a successful return value.\n## Remediation\nUpgrade `openfortivpn` to version 1.12.0 or higher.\n## References\n- [GitHub Commit](https://github.com/adrienverge/openfortivpn/commit/60660e00b80bad0fadcf39aee86f6f8756c94f91)\n- [GitHub Commit](https://github.com/adrienverge/openfortivpn/commit/cd9368c6a1b4ef91d77bb3fdbe2e5bc34aa6f4c4)\n- [GitHub Issue](https://github.com/adrienverge/openfortivpn/issues/536)\n- [Security Advisory](https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/RZEDRWLMRKGVGRSXJMFL4ABTGHIF6GLD/)\n",
          "functions": [],
          "package": "openfortivpn",
          "severity": "medium",
          "exploitMaturity": "no-known-exploit",
          "language": "cpp",
          "packageManager": "unmanaged",
          "semver": {
            "vulnerable": [
              "[,1.12.0)"
            ]
          },
          "publicationTime": "2021-12-14T14:55:50Z",
          "disclosureTime": "2020-02-27T18:15:00Z",
          "identifiers": {
            "CVE": [
              "CVE-2020-7041"
            ],
            "CWE": [
              "CWE-201"
            ]
          },
          "credit": [
            "Unknown"
          ],
          "CVSSv3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
          "cvssScore": 5.3,
          "patches": []
        }
      ],
      "licenses": []
    },
    "packageManager": "unmanaged",
    "licensesPolicy": {
      "severities": {
        "AGPL-1.0": "high",
        "Artistic-1.0": "medium",
        "Artistic-2.0": "medium",
        "CDDL-1.0": "medium",
        "CPOL-1.02": "high",
        "EPL-1.0": "medium",
        "GPL-3.0": "high",
        "MPL-1.1": "medium",
        "MPL-2.0": "medium",
        "MS-RL": "medium",
        "SimPL-2.0": "high",
        "LGPL-3.0": "low",
        "LGPL-2.1": "low",
        "GPL-2.0": "high",
        "LGPL-2.0": "medium",
        "AGPL-3.0": "high",
        "AGPL-3.0-only": "high"
      }
    },
    "org": {
      "name": "michal.brutvan-8fo",
      "id": "4375eaee-5784-404b-805a-b82187f6f61e"
    },
    "dependencyCount": 1
  },
  {
    "ok": false,
    "issues": {
      "vulnerabilities": [
        {
          "id": "SNYK-UNMANAGED-ADRIENVERGEOPENFORTIVPN-2364910",
          "url": "https://snyk.io/vuln/SNYK-UNMANAGED-ADRIENVERGEOPENFORTIVPN-2364910",
          "title": "Uninitialized Memory Exposure",
          "type": "vuln",
          "description": "## Overview\n\nAffected versions of this package are vulnerable to Uninitialized Memory Exposure. An issue was discovered in openfortivpn 1.11.0 when used with OpenSSL 1.0.2 or later. tunnel.c mishandles certificate validation because the hostname check operates on uninitialized memory. The outcome is that a valid certificate is never accepted (only a malformed certificate may be accepted).\n## Remediation\nUpgrade `adrienverge/openfortivpn` to version 1.12.0 or higher.\n## References\n- [GitHub Commit](https://github.com/adrienverge/openfortivpn/commit/9eee997d599a89492281fc7ffdd79d88cd61afc3)\n- [GitHub Commit](https://github.com/adrienverge/openfortivpn/commit/cd9368c6a1b4ef91d77bb3fdbe2e5bc34aa6f4c4)\n- [GitHub Issue](https://github.com/adrienverge/openfortivpn/issues/536)\n- [Security Advisory](https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/LXVMOLZGPWSU3PQQHJUNYFPGEJQQUENK/)\n",
          "functions": [],
          "package": "adrienverge/openfortivpn",
          "severity": "medium",
          "exploitMaturity": "no-known-exploit",
          "language": "cpp",
          "packageManager": "unmanaged",
          "semver": {
            "vulnerable": [
              "[,1.12.0)"
            ]
          },
          "publicationTime": "2021-12-14T14:55:52Z",
          "disclosureTime": "2020-02-27T18:15:00Z",
          "identifiers": {
            "CVE": [
              "CVE-2020-7042"
            ],
            "CWE": [
              "CWE-201"
            ]
          },
          "credit": [
            "Unknown"
          ],
          "CVSSv3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
          "cvssScore": 5.3,
          "patches": []
        },
        {
          "id": "SNYK-UNMANAGED-ADRIENVERGEOPENFORTIVPN-2364908",
          "url": "https://snyk.io/vuln/SNYK-UNMANAGED-ADRIENVERGEOPENFORTIVPN-2364908",
          "title": "Uninitialized Memory Exposure",
          "type": "vuln",
          "description": "## Overview\n\nAffected versions of this package are vulnerable to Uninitialized Memory Exposure. An issue was discovered in openfortivpn 1.11.0 when used with OpenSSL 1.0.2 or later. tunnel.c mishandles certificate validation because an X509_check_host negative error code is interpreted as a successful return value.\n## Remediation\nUpgrade `adrienverge/openfortivpn` to version 1.12.0 or higher.\n## References\n- [GitHub Commit](https://github.com/adrienverge/openfortivpn/commit/60660e00b80bad0fadcf39aee86f6f8756c94f91)\n- [GitHub Commit](https://github.com/adrienverge/openfortivpn/commit/cd9368c6a1b4ef91d77bb3fdbe2e5bc34aa6f4c4)\n- [GitHub Issue](https://github.com/adrienverge/openfortivpn/issues/536)\n- [Security Advisory](https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/RZEDRWLMRKGVGRSXJMFL4ABTGHIF6GLD/)\n",
          "functions": [],
          "package": "adrienverge/openfortivpn",
          "severity": "medium",
          "exploitMaturity": "no-known-exploit",
          "language": "cpp",
          "packageManager": "unmanaged",
          "semver": {
            "vulnerable": [
              "[,1.12.0)"
            ]
          },
          "publicationTime": "2021-12-14T14:55:50Z",
          "disclosureTime": "2020-02-27T18:15:00Z",
          "identifiers": {
            "CVE": [
              "CVE-2020-7041"
            ],
            "CWE": [
              "CWE-201"
            ]
          },
          "credit": [
            "Unknown"
          ],
          "CVSSv3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
          "cvssScore": 5.3,
          "patches": []
        },
        {
          "id": "SNYK-UNMANAGED-ADRIENVERGEOPENFORTIVPN-2364909",
          "url": "https://snyk.io/vuln/SNYK-UNMANAGED-ADRIENVERGEOPENFORTIVPN-2364909",
          "title": "Improper Certificate Validation",
          "type": "vuln",
          "description": "## Overview\n\nAffected versions of this package are vulnerable to Improper Certificate Validation. An issue was discovered in openfortivpn 1.11.0 when used with OpenSSL before 1.0.2. tunnel.c mishandles certificate validation because hostname comparisons do not consider '\\0' characters, as demonstrated by a good.example.com\\x00evil.example.com attack.\n## Remediation\nUpgrade `adrienverge/openfortivpn` to version 1.12.0 or higher.\n## References\n- [GitHub Commit](https://github.com/adrienverge/openfortivpn/commit/6328a070ddaab16faaf008cb9a8a62439c30f2a8)\n- [GitHub Commit](https://github.com/adrienverge/openfortivpn/commit/cd9368c6a1b4ef91d77bb3fdbe2e5bc34aa6f4c4)\n- [GitHub Issue](https://github.com/adrienverge/openfortivpn/issues/536)\n",
          "functions": [],
          "package": "adrienverge/openfortivpn",
          "severity": "critical",
          "exploitMaturity": "no-known-exploit",
          "language": "cpp",
          "packageManager": "unmanaged",
          "semver": {
            "vulnerable": [
              "[,1.12.0)"
            ]
          },
          "publicationTime": "2021-12-14T14:55:49.737824Z",
          "disclosureTime": "2020-02-27T18:15:00Z",
          "identifiers": {
            "CVE": [
              "CVE-2020-7043"
            ],
            "CWE": [
              "CWE-295"
            ]
          },
          "credit": [
            "Unknown"
          ],
          "CVSSv3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
          "cvssScore": 9.1,
          "patches": []
        }
      ],
      "licenses": []
    },
    "packageManager": "unmanaged",
    "licensesPolicy": {
      "severities": {
        "AGPL-1.0": "high",
        "Artistic-1.0": "medium",
        "Artistic-2.0": "medium",
        "CDDL-1.0": "medium",
        "CPOL-1.02": "high",
        "EPL-1.0": "medium",
        "GPL-3.0": "high",
        "MPL-1.1": "medium",
        "MPL-2.0": "medium",
        "MS-RL": "medium",
        "SimPL-2.0": "high",
        "LGPL-3.0": "low",
        "LGPL-2.1": "low",
        "GPL-2.0": "high",
        "LGPL-2.0": "medium",
        "AGPL-3.0": "high",
        "AGPL-3.0-only": "high"
      }
    },
    "org": {
      "name": "michal.brutvan-8fo",
      "id": "4375eaee-5784-404b-805a-b82187f6f61e"
    },
    "dependencyCount": 1
  }
]

```

## About the modules

The [snyk_cpp](./src/snyk_cpp.py) provides a SnykCpp class that serves as a wrapper around the experimental Snyk test API. It's example usage is in [examples/curl.py](./examples/curl.py) and  [examples/cyclonedx.py](./examples/cyclonedx.py).

The `snyk_cpp` module provides the `SnykCpp` class with a function called `test` that takes in a package name and a version and performs a very basic lookup in the static list of coordinates to identify the most likely packages that could match the name. For each coordinate it finds, it calls the test API to return a set of sets of issues.

```python
    def test(self, name: str, version: str) -> dict
```


## Testing Conan projects

Testing a project using Conan package manager can be done via an intermediate CycloneDX document. The CycloneDX document can be generated from `conanfile.txt` or `conanfile.py` using the [CycloneDX-Conan](https://github.com/CycloneDX/cyclonedx-conan) tool.
