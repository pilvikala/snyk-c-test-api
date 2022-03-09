# this is an example of testing a single package by its name and version

import json
from snyk_cpp import SnykCpp
from snyk_token import get_token

def main():
    token = get_token()
    snykCpp = SnykCpp(token)
    try:
        result = snykCpp.test('curl', '7.58.0')
        print(json.dumps(result))
    except Exception as err:
        print(err)

main()