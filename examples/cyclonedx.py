# this tests a CycloneDX SBOM with C++ packages for their vulnerabilities using an experimental Snyk Test API
# usage: PYTHONPATH=src python examples/cyclonedx.py <path-to-sbom>
# the current directory has an example cyclonedx-bom.json

import sys
import json
from snyk_cpp import SnykCpp
from snyk_token import get_token


def get_path_or_exit():
    if len(sys.argv) > 1:
        return sys.argv[1]
    print("usage: PYTHONPATH=src python examples/cyclonedx.py <path-to-sbom>")
    exit(1)

def get_sbom(path: str):
    with open(path) as file:
        return json.loads(file.read())

def get_components_from_sbom(sbom: dict):
    components = []
    if not "components" in sbom.keys():
        print("Invalid SBOM format")
        exit(1)
    for component in sbom["components"]:
        components.append(
            {"name": component["name"], "version": component["version"]},
        )
    return components

def print_issues(vulnerabilities):
    for vuln in vulnerabilities:
        print("  [{}]  {}: {}".format(vuln["severity"], vuln["title"], vuln["url"]))

def print_result(result):
    for package_result in result:
        if ("error" in package_result.keys()):
            print(package_result["error"])
            return

        if(len(package_result["issues"]["vulnerabilities"]) == 0):
            print("no issues found\r\n")
        else:
            print_issues(package_result["issues"]["vulnerabilities"])

def main():
    token = get_token()
    path = get_path_or_exit()
    sbom = get_sbom(path)
    components = get_components_from_sbom(sbom)
    snyk_cpp = SnykCpp(token)
    for component in components:
        print("\r\ntesting {} {}".format(component["name"], component["version"]))
        result = snyk_cpp.test(component["name"], component["version"])
        print_result(result)
    print()

main()