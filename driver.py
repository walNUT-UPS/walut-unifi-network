import os
import time
import json
import math
import typing as t
from dataclasses import dataclass

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


@dataclass
class _Cfg:
    hostname: str
    base_path: str
    api_key: str
    verify_ssl: bool
    auth_header_name: str
    auth_scheme: str


class UnifiNetworkDriver:
    """
    UniFi Network Integration Driver (API v9.4.x: /proxy/network/integration/v1)
    Endpoints and shapes per your PDF:
      - GET /v1/info (application info)                                   [About/Application]  (applicationVersion)
      - GET /v1/sites (list sites; paginated, filter)                     [Sites]             (id, internalReference, name)
      - GET /v1/sites/{siteId}/devices (+/{deviceId}, actions: RESTART)   [Devices]           (list/detail; POST actions)
      - POST /v1/sites/{siteId}/devices/{deviceId}/interfaces/ports/{portIdx}/actions (POWER_CYCLE)
      - GET /v1/sites/{siteId}/clients (+/{clientId})                     [Clients]
      - Vouchers: GET/POST/DELETE /v1/sites/{siteId}/hotspot/vouchers (+/{voucherId})
    """

    def __init__(self, instance, secrets: dict | None = None):
        # Framework interface: instance is IntegrationInstance object with config attribute
        secrets = secrets or {}
        config = instance.config if hasattr(instance, 'config') else instance
        
        self.cfg = _Cfg(
            hostname=config["hostname"],
            base_path=config.get("base_path", "/proxy/network/integration/v1"),
            api_key=(secrets.get("api_key") or config.get("api_key")),
            verify_ssl=bool(config.get("verify_ssl", True)),
            auth_header_name=config.get("auth_header_name", "Authorization"),
            auth_scheme=config.get("auth_scheme", "Bearer"),
        )
        if not self.cfg.api_key:
            raise ValueError("api_key is required")

        base = self.cfg.base_path.rstrip("/")
        host = self.cfg.hostname
        if not host.startswith("http"):
            host = f"https://{host}"
        self.base_url = f"{host}{base}"

        self._session = requests.Session()
        # Retry/backoff: respect Retry-After; cap sensibly to avoid hammering
        retries = Retry(
            total=5,
            read=5,
            connect=3,
            backoff_factor=0.6,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "POST", "DELETE"])
        )
        self._session.mount("https://", HTTPAdapter(max_retries=retries))
        self._session.mount("http://", HTTPAdapter(max_retries=retries))

    # ---------- util ----------

    def _headers(self) -> dict:
        """
        Docs say 'API Key' but omit the exact header. Make this configurable and
        attempt a sane fallback sequence:
          1) If auth_header_name == "Authorization": "Authorization: <scheme> <key>" (default scheme 'Bearer')
          2) Else: "<auth_header_name>: <key>"  (e.g., X-API-Key)
          3) If first attempt 401/403, try alternates once per process lifetime.
        """
        if self.cfg.auth_header_name.lower() == "authorization":
            if self.cfg.auth_scheme:
                return {"Authorization": f"{self.cfg.auth_scheme} {self.cfg.api_key}"}
            else:
                # raw token in Authorization header (rare, but supported)
                return {"Authorization": self.cfg.api_key}
        # Non-standard header case (e.g., X-API-Key, X-Auth-Token)
        return {self.cfg.auth_header_name: self.cfg.api_key}

    def _request(self, method: str, path: str, *, params=None, json=None, expected=200):
        url = f"{self.base_url}{path}"
        resp = self._session.request(
            method, url, headers=self._headers(), params=params, json=json, verify=self.cfg.verify_ssl, timeout=30
        )
        # If 401/403 and we used Authorization Bearer, try common alternates once
        if resp.status_code in (401, 403):
            alt_headers_list = []
            # Build alternates only if we used the default combo
            if self.cfg.auth_header_name.lower() == "authorization":
                alt_headers_list = [
                    {"X-API-Key": self.cfg.api_key},
                    {"X-Auth-Token": self.cfg.api_key},
                ]
            for alt in alt_headers_list:
                resp = self._session.request(
                    method, url, headers=alt, params=params, json=json, verify=self.cfg.verify_ssl, timeout=30
                )
                if resp.status_code not in (401, 403):
                    break

        # Honor Retry-After manually on 429 (requests Retry handles many cases but we’ll be explicit)
        if resp.status_code == 429:
            ra = resp.headers.get("Retry-After")
            if ra:
                try:
                    delay = int(ra)
                    time.sleep(min(delay, 10))
                    resp = self._session.request(
                        method, url, headers=self._headers(), params=params, json=json, verify=self.cfg.verify_ssl, timeout=30
                    )
                except Exception:
                    pass

        if expected is not None and resp.status_code != expected:
            # Bubble up UniFi standardized error envelope (statusCode/statusName/message/...)
            raise RuntimeError(f"HTTP {resp.status_code} on {method} {path}: {resp.text}")

        if resp.status_code == 204 or not resp.content:
            return None
        return resp.json()

    def _paginate(self, path: str, *, params=None, page_size=100, limit_upper=1000) -> list:
        """
        UniFi list endpoints expose offset/limit and return offset, limit, count, totalCount, data[].
        We'll iterate with a sensible page size respecting endpoint upper bounds (e.g., 200 for clients/devices; 1000 vouchers).
        """
        params = dict(params or {})
        params.setdefault("offset", 0)
        params.setdefault("limit", min(page_size, limit_upper))
        items: list = []
        while True:
            page = self._request("GET", path, params=params, expected=200)
            data = page.get("data", [])
            items.extend(data)
            offset = page.get("offset", params["offset"])
            count = page.get("count", len(data))
            total = page.get("totalCount", len(items))
            next_offset = offset + count
            if next_offset >= total or count == 0:
                break
            params["offset"] = next_offset
        return items

    # ---------- required by framework ----------

    def test_connection(self) -> dict:
        """
        Hit GET /v1/info → {"applicationVersion": "..."} (PDF: About Application / Get Application Info).
        """
        t0 = time.time()
        try:
            info = self._request("GET", "/info", expected=200)
            latency = int((time.time() - t0) * 1000)
            version = info.get("applicationVersion")
            return {"status": "connected", "latency_ms": latency, "details": f"UniFi Network {version}"}
        except Exception as e:
            latency = int((time.time() - t0) * 1000)
            return {"status": "error", "latency_ms": latency, "details": str(e)}

    # ---------- inventory.list ----------

    def inventory_list(self, target_type: str, active_only: bool = True, options: dict | None = None) -> list:
        """
        target_type normalized to snake_case by the core (per GPT.md).
        Supported: "site", "device", "client", "voucher".
        """
        options = options or {}
        site_id = options.get("site_id")  # required for device/client/voucher listing
        filter_expr = options.get("filter")

        if target_type == "site":
            params = {}
            if filter_expr:
                params["filter"] = filter_expr
            return self._paginate("/sites", params=params, page_size=100, limit_upper=1000)

        if target_type == "device":
            if not site_id:
                raise ValueError("options.site_id is required for device listing")
            params = {}
            return self._paginate(f"/sites/{site_id}/devices", params=params, page_size=200, limit_upper=200)

        if target_type == "client":
            if not site_id:
                raise ValueError("options.site_id is required for client listing")
            params = {}
            if filter_expr:
                params["filter"] = filter_expr  # supports eq/ne/gt/... per Filtering section
            return self._paginate(f"/sites/{site_id}/clients", params=params, page_size=200, limit_upper=200)

        if target_type == "voucher":
            if not site_id:
                raise ValueError("options.site_id is required for voucher listing")
            params = {"limit": 1000}
            if filter_expr:
                params["filter"] = filter_expr  # supports eq, like, in, notIn etc.
            return self._paginate(f"/sites/{site_id}/hotspot/vouchers", params=params, page_size=1000, limit_upper=1000)

        raise ValueError(f"unsupported target_type: {target_type}")

    # ---------- unifi.application.info ----------

    def unifi_application_info(self, verb: str, target: dict, dry_run: bool = False, **params) -> dict:
        if verb != "get":
            raise ValueError("unsupported verb for unifi.application.info")
        info = self._request("GET", "/info", expected=200)
        return {"status": "ok", "info": info}

    # ---------- unifi.device.lifecycle ----------

    def unifi_device_lifecycle(self, verb: str, target: dict, dry_run: bool = False, **params) -> dict:
        """
        POST /v1/sites/{siteId}/devices/{deviceId}/actions  { "action": "RESTART" }
        """
        site_id = (target.get("site_id") or params.get("site_id"))
        device_id = (target.get("external_id") or target.get("id") or params.get("device_id"))
        if not site_id or not device_id:
            raise ValueError("site_id and device_id required")
        plan = {
            "action": "device.restart",
            "target_id": device_id,
            "expected_effect": "Device will restart.",
        }
        if dry_run:
            return {"status": "plan", "plan": plan}

        payload = {"action": "RESTART"}  # per PDF Devices → Execute Device Action
        self._request("POST", f"/sites/{site_id}/devices/{device_id}/actions", json=payload, expected=200)
        return {"status": "ok", "result": {"device_id": device_id, "action": "RESTART"}}

    # ---------- unifi.port.lifecycle ----------

    def unifi_port_lifecycle(self, verb: str, target: dict, dry_run: bool = False, **params) -> dict:
        """
        POST /v1/sites/{siteId}/devices/{deviceId}/interfaces/ports/{portIdx}/actions { "action": "POWER_CYCLE" }
        """
        if verb != "power-cycle":
            raise ValueError("unsupported verb for unifi.port.lifecycle")
        site_id = (target.get("site_id") or params.get("site_id"))
        device_id = (target.get("device_id") or params.get("device_id"))
        port_idx = (target.get("port_idx") or params.get("port_idx"))
        if not site_id or not device_id or port_idx is None:
            raise ValueError("site_id, device_id and port_idx required")
        plan = {
            "action": "port.power-cycle",
            "target_id": f"{device_id}:{port_idx}",
            "expected_effect": "Port will be power-cycled.",
        }
        if dry_run:
            return {"status": "plan", "plan": plan}

        payload = {"action": "POWER_CYCLE"}  # per PDF Ports → Execute Port Action
        self._request("POST", f"/sites/{site_id}/devices/{device_id}/interfaces/ports/{port_idx}/actions",
                      json=payload, expected=200)
        return {"status": "ok", "result": {"device_id": device_id, "port_idx": port_idx, "action": "POWER_CYCLE"}}

    # ---------- unifi.client.access ----------

    def unifi_client_access(self, verb: str, target: dict, dry_run: bool = False, **params) -> dict:
        """
        POST /v1/sites/{siteId}/clients/{clientId}/actions
          - AUTHORIZE_GUEST_ACCESS (+ optional time/data/rate limits)
          - UNAUTHORIZE_GUEST_ACCESS
        """
        site_id = (target.get("site_id") or params.get("site_id"))
        client_id = (target.get("external_id") or target.get("id") or params.get("client_id"))
        if not site_id or not client_id:
            raise ValueError("site_id and client_id required")

        action_map = {
            "authorize-guest": "AUTHORIZE_GUEST_ACCESS",
            "unauthorize-guest": "UNAUTHORIZE_GUEST_ACCESS",
        }
        if verb not in action_map:
            raise ValueError("unsupported verb for unifi.client.access")

        # Map params to API field names from PDF (Generate/Authorize limits share naming style)
        payload = {"action": action_map[verb]}
        for k_src, k_dst in [
            ("time_limit_minutes", "timeLimitMinutes"),
            ("data_usage_limit_mbytes", "dataUsageLimitMBytes"),
            ("rx_rate_limit_kbps", "rxRateLimitKbps"),
            ("tx_rate_limit_kbps", "txRateLimitKbps"),
        ]:
            if params.get(k_src) is not None:
                payload[k_dst] = params[k_src]

        plan = {
            "action": f"client.{verb}",
            "target_id": client_id,
            "params": {k: v for k, v in payload.items() if k != "action"},
            "expected_effect": "Client guest access state will change accordingly.",
            "reversible_with": "unauthorize-guest" if verb == "authorize-guest" else "authorize-guest",
        }
        if dry_run:
            return {"status": "plan", "plan": plan}

        res = self._request("POST", f"/sites/{site_id}/clients/{client_id}/actions", json=payload, expected=200)
        return {"status": "ok", "result": res or {"client_id": client_id, "action": payload["action"]}}

    # ---------- unifi.voucher.lifecycle ----------

    def unifi_voucher_lifecycle(self, verb: str, target: dict, dry_run: bool = False, **params) -> dict:
        """
        - generate: POST /v1/sites/{siteId}/hotspot/vouchers
        - delete:   DELETE /v1/sites/{siteId}/hotspot/vouchers?filter=...
                    or DELETE /v1/sites/{siteId}/hotspot/vouchers/{voucherId}
        """
        site_id = (target.get("site_id") or params.get("site_id"))
        if not site_id:
            raise ValueError("site_id required")

        if verb == "generate":
            payload = {
                "count": int(params.get("count", 1)),
                "name": params["name"],
                "authorizedGuestLimit": int(params.get("authorized_guest_limit", 1)),
                "timeLimitMinutes": int(params["time_limit_minutes"]),
            }
            # Optional knobs
            if params.get("data_usage_limit_mbytes") is not None:
                payload["dataUsageLimitMBytes"] = int(params["data_usage_limit_mbytes"])
            if params.get("rx_rate_limit_kbps") is not None:
                payload["rxRateLimitKbps"] = int(params["rx_rate_limit_kbps"])
            if params.get("tx_rate_limit_kbps") is not None:
                payload["txRateLimitKbps"] = int(params["tx_rate_limit_kbps"])

            plan = {
                "action": "voucher.generate",
                "target_id": f"site:{site_id}",
                "params": {k: v for k, v in payload.items()},
                "expected_effect": f"{payload['count']} voucher(s) will be created.",
            }
            if dry_run:
                return {"status": "plan", "plan": plan}

            res = self._request("POST", f"/sites/{site_id}/hotspot/vouchers", json=payload, expected=201)
            return {"status": "ok", "result": res}

        if verb == "delete":
            voucher_id = target.get("external_id") or target.get("id") or params.get("voucher_id")
            filter_expr = params.get("filter")
            if voucher_id:
                plan = {
                    "action": "voucher.delete",
                    "target_id": voucher_id,
                    "expected_effect": "Voucher will be deleted.",
                }
                if dry_run:
                    return {"status": "plan", "plan": plan}
                res = self._request("DELETE", f"/sites/{site_id}/hotspot/vouchers/{voucher_id}", expected=200)
                return {"status": "ok", "result": res}
            if not filter_expr:
                raise ValueError("either target.id or params.filter is required for delete")
            plan = {
                "action": "voucher.delete",
                "target_id": f"site:{site_id}",
                "params": {"filter": filter_expr},
                "expected_effect": "Matching vouchers will be deleted.",
            }
            if dry_run:
                return {"status": "plan", "plan": plan}
            res = self._request("DELETE", f"/sites/{site_id}/hotspot/vouchers", params={"filter": filter_expr}, expected=200)
            return {"status": "ok", "result": res}

        raise ValueError("unsupported verb for unifi.voucher.lifecycle")