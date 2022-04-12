# this tests a CycloneDX SBOM with C++ packages for their vulnerabilities using an experimental Snyk Test API
# usage: PYTHONPATH=src python examples/cyclonedx.py <path-to-sbom>
# the current directory has an example cyclonedx-bom.json

import sys
import json
from snyk_cpp import SnykCpp
from snyk_token import get_token

# gets the path to a CycloneDX document from the cmdline arguments 
def get_path_or_exit():
    if len(sys.argv) > 1:
        return sys.argv[1]
    print("usage: PYTHONPATH=src python examples/cyclonedx.py <path-to-sbom>")
    exit(1)

# loads CycloneDX from a json file
def load_sbom(path: str):
    with open(path) as file:
        return json.loads(file.read())

# loads the list of components defined in the CycloneDX document
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

def print_issues(package_name, component_name, vulnerabilities):
    # skip matches that do not correspond to the standard naming
    # the following check avoids printing issues for packages with short names that could be a substring of another package,
    # for example apr - haproxy - libapreq2
    if package_name is None:
        return
    if not package_name.endswith(component_name):        
        return
    print("matched package name: {}".format(package_name))
    for vuln in vulnerabilities:
            print("  [{}]  {}: {}".format(vuln["severity"], vuln["title"], vuln["url"]))

# check the list of returned issues to get a package name from the set. This is used to validate issues were returned for the
# actual package specified in the SBOM
def get_package_name_from_first_issue(vulnerabilities):
    if len(vulnerabilities) > 0:
        return vulnerabilities[0]["package"]
    return None

# prints the result of one API call
def print_result(component_name, result):
    for package_result in result:
        if ("error" in package_result.keys()):
            if package_result["error"].endswith(" was not found."):
                # when a package is not found in VulnDB, it means we don't have vulnerabilities for it.
                # let's make the error message less confusing
                print("no issues found")
            else:
                print(package_result["error"])
            return
        package_name = get_package_name_from_first_issue(package_result["issues"]["vulnerabilities"])
        print_issues(package_name, component_name, package_result["issues"]["vulnerabilities"])

def main():
    token = get_token()
    path = get_path_or_exit()
    sbom = load_sbom(path)
    components = get_components_from_sbom(sbom)
    snyk_cpp = SnykCpp(token)
    for component in components:
        print("\r\ntesting {} {}".format(component["name"], component["version"]))
        result = snyk_cpp.test(component["name"], component["version"])
        print_result(component["name"], result)
    print()

main()