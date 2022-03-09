import os

def get_token() -> str:
    try:
        token = os.environ['SNYK_TOKEN']
        if not token:
            raise ValueError()
    except:
        print("SNYK_TOKEN variable is not set")
        raise ValueError()
    return token
