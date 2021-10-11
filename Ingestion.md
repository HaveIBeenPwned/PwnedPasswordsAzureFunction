# Hash Ingestion

*SOME INTRO TEXT*

## Submitting hashes for ingestion
The PwnedPasswords ingestion endpoint can be found at the `/append` path. To send passwords for ingestiong you'll need to send a JSON array with each element containing a `sha1Hash`, `ntlmHash` and a `prevalence` for each password.

Example JSON document for the passwords `Passw0rd!` and `hunter2` :
```json
[
    {
        "sha1Hash": "F4A69973E7B0BF9D160F9F60E3C3ACD2494BEB0D",
        "ntlmHash": "FC525C9683E8FE067095BA2DDC971889",
        "prevalence": 15
    },
    {
        "sha1Hash": "25AFF7F4B1BB747833F5175789A1998B31CA4ED4",
        "ntlmHash": "6608E4BC7B2B7A5F77CE3573570775AF",
        "prevalence": 25
    }
]
```

The ingestion endpoint is authenticated with [Azure API Management](https://azure.microsoft.com/en-us/services/api-management/) and requires a valid subscription key to be sent with the `Ocp-Apim-Subscription-Key` HTTP header. Here is an example request:
```http
POST /append HTTP/1.1
Host: api.pwnedpasswords.com
Ocp-Apim-Subscription-Key: __EXAMPLE_SUBSCRIPTION_KEY__
Content-Type: application/json
Content-Length: 329

[
    {
        "sha1Hash": "F4a69973E7B0BF9D160F9F60E3C3ACD2494BEB0D",
        "ntlmHash": "FC525C9683E8FE067095BA2DDC971889",
        "prevalence": 15
    },
    {
        "sha1Hash": "25AFF7F4B1BB747833F5175789A1998B31CA4ED4",
        "ntlmHash": "6608E4BC7B2B7A5F77CE3573570775AF",
        "prevalence": 25
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
To confirm the submission, the transaction ID must be submitted to the `/append/confirm` endpoint, again providing the API Management subscription key. This step is intentional to reduce accidental multiple submissions. Non-confirmed submissions will be deleted if they aren't confirmed within 24 hours.

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

If the transaction is found and has not been confirmed already, the API will respond with a 200 OK response.
