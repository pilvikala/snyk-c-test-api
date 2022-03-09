# SPDX-License-Identifier: MIT
# Source: https://github.com/snyk-labs/pysnyk

import requests

ENDPOINT_URL = "https://us-east1-snyk-main.cloudfunctions.net/test-cpp"

class SnykCpp:
    def __init__(self, token: str):
        if not token:
            raise ValueError("token")
        self.token = token
        
    def test(self, name: str, version: str) -> dict:
        resp = requests.get("{}/{}/{}".format(ENDPOINT_URL, name, version), 
                            headers = {
                                "Authorization": "token {}".format(self.token)
                            })
        try:
            return resp.json()
        except:
            return [{"error": resp.text}]
