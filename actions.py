import urllib.request
import urllib.parse
import json
import logging

LOG = logging.getLogger(__name__)

# Set the destination where the HASS API is reachable
HASS_API = "http://127.0.0.1:8123/api/"
# If a password is required to access the API, set it in the form of "password"
HASS_API_PASSWORD = None

def toggle_light():
    LOG.info("Toggeling light")
    headers = {"Content-Type": "application/json"}

    service = "services/light/toggle"
    data = {
        "entity_id": "light.yourlight"
    }

    data = json.dumps(data).encode("utf-8")
    if HASS_API_PASSWORD:
        headers["x-ha-access"] = HASS_API_PASSWORD
        headers["Content-Length"] = len(data)
    req = urllib.request.Request("%s%s" % (HASS_API, service),
                                 data, headers=headers, method='POST')
    with urllib.request.urlopen(req) as response:
        res = json.loads(response.read().decode('utf-8'))
        return bool(res)
    return False
