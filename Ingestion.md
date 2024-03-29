# Hash Ingestion

*SOME INTRO TEXT*

## Submitting hashes for ingestion
The PwnedPasswords ingestion endpoint can be found at the `/ingestion/append` path. To submit passwords for ingestion you'll need to send a JSON array with each element containing a `sha1Hash`, `ntlmHash` and a `prevalence` for each password.

Example JSON document for the passwords `Passw0rd!` and `hunter2` :
```json
[
    {
        "sha1": "F4A69973E7B0BF9D160F9F60E3C3ACD2494BEB0D",
        "ntlm": "FC525C9683E8FE067095BA2DDC971889",
        "num": 15
    },
    {
        "sha1": "F3BBBD66A63D4BF1747940578EC3D0103530E21D",
        "ntlm": "6608E4BC7B2B7A5F77CE3573570775AF",
        "num": 25
    }
]
```

The ingestion endpoint is authenticated with [Azure API Management](https://azure.microsoft.com/en-us/services/api-management/) and requires a valid subscription key to be sent with the `Ocp-Apim-Subscription-Key` HTTP header. Here is an example request:
```http
POST /ingestion/append HTTP/1.1
Host: api.pwnedpasswords.com
Ocp-Apim-Subscription-Key: __EXAMPLE_SUBSCRIPTION_KEY__
Content-Type: application/json
Content-Length: 329

[
    {
        "sha1": "F4A69973E7B0BF9D160F9F60E3C3ACD2494BEB0D",
        "ntlm": "FC525C9683E8FE067095BA2DDC971889",
        "num": 15
    },
    {
        "sha1": "F3BBBD66A63D4BF1747940578EC3D0103530E21D",
        "ntlm": "6608E4BC7B2B7A5F77CE3573570775AF",
        "num": 25
    }
]
```

If the entry is valid and accepted the API will return a 200 OK response containing a transaction id.

Example response:
```json
{
    "transactionId": "c2c59a12-4788-40b3-b8b4-4fa2e720aab8"
}
```

## Confirming hash submission
To confirm the submission, the transaction ID must be submitted to the `/ingestion/append/confirm` endpoint, again providing the API Management subscription key. This step is intentional to reduce accidental multiple submissions. Non-confirmed submissions will be deleted if they aren't confirmed within 24 hours.

Example request:
```http
POST /append/confirm HTTP/1.1
Host: api.pwnedpasswords.com
Ocp-Apim-Subscription-Key: __EXAMPLE_SUBSCRIPTION_KEY__
Content-Type: application/json
Content-Length: 65

{
    "transactionId": "c2c59a12-4788-40b3-b8b4-4fa2e720aab8"
}
```

If the transaction is found and has not been confirmed already, the API will respond with a 200 OK response. The hashes will then be queued and processes. The updates won't show up immediately in the blobs, but they should have their cache purged at 00:30 UTC the next day.
