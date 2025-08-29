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

        if target_type == "port":
            if not site_id:
                raise ValueError("options.site_id is required for port listing")
            # Port listing requires getting device details and extracting port info
            devices = self._paginate(f"/sites/{site_id}/devices", params={}, page_size=200, limit_upper=200)
            ports = []
            for device in devices:
                device_detail = self._request("GET", f"/sites/{site_id}/devices/{device.get('id')}")
                interfaces = device_detail.get("interfaces", {})
                device_ports = interfaces.get("ports", [])
                for port in device_ports:
                    port_obj = {
                        "type": "port",
                        "external_id": f"{device.get('id')}:{port.get('idx')}",
                        "name": f"{device.get('displayName', device.get('name', 'Unknown'))}-Port-{port.get('idx')}",
                        "attrs": {
                            "device_id": device.get("id"),
                            "device_name": device.get("displayName", device.get("name")),
                            "port_idx": port.get("idx"),
                            "state": port.get("state"),
                            "connector": port.get("connector"),
                            "speed_mbps": port.get("speedMbps"),
                            "max_speed_mbps": port.get("maxSpeedMbps"),
                            "poe_capable": "poe" in port,
                            "poe_enabled": port.get("poe", {}).get("enabled", False),
                            "poe_standard": port.get("poe", {}).get("standard"),
                            "poe_type": port.get("poe", {}).get("type"),
                            "poe_state": port.get("poe", {}).get("state")
                        }
                    }
                    if active_only:
                        # Consider port active if link is up OR PoE is delivering power
                        link_up = port.get("state", "").upper() == "UP"
                        poe_delivering = port.get("poe", {}).get("state", "").upper() == "UP"
                        if link_up or poe_delivering:
                            ports.append(port_obj)
                    else:
                        ports.append(port_obj)
            return ports

        raise ValueError(f"unsupported target_type: {target_type}")

    # ---------- unifi.application.info ----------

    def unifi_application_info(self, verb: str, target: dict, dry_run: bool = False, **params) -> dict:
        if verb != "get":
            raise ValueError("unsupported verb for unifi.application.info")
        info = self._request("GET", "/info", expected=200)
        return {"status": "ok", "info": info}

    # ---------- unifi.device.power ----------

    def unifi_device_power(self, verb: str, target: dict, dry_run: bool = False, **params) -> dict:
        """
        POST /v1/sites/{siteId}/devices/{deviceId}/actions  { "action": "RESTART" }
        """
        # Handle both dict and Target object from loader
        if hasattr(target, 'external_id'):  # Target object
            site_id = params.get("site_id")
            device_id = target.external_id
        else:  # dict
            site_id = (target.get("site_id") if target else None) or params.get("site_id")
            device_id = (target.get("external_id") or target.get("id") if target else None) or params.get("device_id")
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

    # ---------- unifi.port.power ----------

    def unifi_port_power(self, verb: str, target: dict, dry_run: bool = False, **params) -> dict:
        """
        POST /v1/sites/{siteId}/devices/{deviceId}/interfaces/ports/{portIdx}/actions { "action": "POWER_CYCLE" }
        """
        if verb != "power_cycle":
            raise ValueError("unsupported verb for unifi.port.power")
        # Handle both dict and Target object from loader
        if hasattr(target, 'external_id'):  # Target object
            site_id = params.get("site_id")
            device_id = params.get("device_id")
            port_idx = params.get("port_idx")
        else:  # dict
            site_id = (target.get("site_id") if target else None) or params.get("site_id")
            device_id = (target.get("device_id") if target else None) or params.get("device_id")
            port_idx = (target.get("port_idx") if target else None) or params.get("port_idx")
        if not site_id or not device_id or port_idx is None:
            raise ValueError("site_id, device_id and port_idx required")
        plan = {
            "action": "port.power_cycle",
            "target_id": f"{device_id}:{port_idx}",
            "expected_effect": "Port will be power-cycled.",
        }
        if dry_run:
            return {"status": "plan", "plan": plan}

        payload = {"action": "POWER_CYCLE"}  # per PDF Ports → Execute Port Action
        self._request("POST", f"/sites/{site_id}/devices/{device_id}/interfaces/ports/{port_idx}/actions",
                      json=payload, expected=200)
        return {"status": "ok", "result": {"device_id": device_id, "port_idx": port_idx, "action": "POWER_CYCLE"}}

    # ---------- unifi.power.discover ----------

    def unifi_power_discover(self, verb: str, target: dict, dry_run: bool = False, **params) -> dict:
        """
        Map power-related infrastructure for walNUT power management.
        Returns detailed power mapping of sites, devices, and PoE-capable ports.
        """
        if verb != "map":
            raise ValueError("unsupported verb for unifi.power.discover")
        
        # Handle both dict and Target object from loader
        if hasattr(target, 'type'):  # Target object
            target_type = target.type
            site_id = params.get("site_id")
        else:  # dict
            target_type = target.get("type", "site") if target else "site"
            site_id = (target.get("site_id") if target else None) or params.get("site_id")
        
        if target_type == "site":
            # Map all sites with basic info
            sites = self.inventory_list("site", active_only=False, options=None)
            power_map = {
                "action": "power.map.sites",
                "sites": [],
                "summary": {"total_sites": len(sites)}
            }
            for site in sites:
                site_info = {
                    "site_id": site.get("external_id") or site.get("id"),
                    "name": site.get("name"),
                    "devices_count": 0,
                    "poe_ports_count": 0
                }
                power_map["sites"].append(site_info)
            
            if dry_run:
                return {"status": "plan", "plan": {"action": "power.discover.sites", "expected_effect": f"Map {len(sites)} sites for power analysis"}}
            return {"status": "ok", "power_map": power_map}
            
        elif target_type == "device":
            if not site_id:
                raise ValueError("site_id required for device power mapping")
            
            devices = self.inventory_list("device", active_only=False, options={"site_id": site_id})
            power_map = {
                "action": "power.map.devices", 
                "site_id": site_id,
                "devices": [],
                "summary": {"total_devices": len(devices), "poe_capable_devices": 0}
            }
            
            for device in devices:
                device_id = device.get("external_id") or device.get("id")
                device_detail = self._request("GET", f"/sites/{site_id}/devices/{device_id}")
                
                interfaces = device_detail.get("interfaces", {})
                ports = interfaces.get("ports", [])
                poe_ports = [p for p in ports if "poe" in p]
                
                device_info = {
                    "device_id": device_id,
                    "name": device.get("name"),
                    "model": device_detail.get("model"),
                    "state": device_detail.get("state"),
                    "total_ports": len(ports),
                    "poe_ports_count": len(poe_ports),
                    "poe_capable": len(poe_ports) > 0,
                    "power_priority": "high" if device_detail.get("model", "").lower().find("gateway") >= 0 else "medium"
                }
                power_map["devices"].append(device_info)
                if device_info["poe_capable"]:
                    power_map["summary"]["poe_capable_devices"] += 1
            
            if dry_run:
                return {"status": "plan", "plan": {"action": "power.discover.devices", "expected_effect": f"Map {len(devices)} devices for power analysis"}}
            return {"status": "ok", "power_map": power_map}
            
        elif target_type == "port":
            if not site_id:
                raise ValueError("site_id required for port power mapping")
                
            ports = self.inventory_list("port", active_only=False, options={"site_id": site_id})
            poe_ports = [p for p in ports if p.get("attrs", {}).get("poe_capable", False)]
            
            power_map = {
                "action": "power.map.ports",
                "site_id": site_id, 
                "poe_ports": [],
                "summary": {
                    "total_ports": len(ports),
                    "poe_capable_ports": len(poe_ports),
                    "poe_enabled_ports": len([p for p in poe_ports if p.get("attrs", {}).get("poe_enabled", False)])
                }
            }
            
            for port in poe_ports:
                attrs = port.get("attrs", {})
                port_info = {
                    "port_id": port.get("external_id"),
                    "name": port.get("name"),
                    "device_id": attrs.get("device_id"),
                    "device_name": attrs.get("device_name"),
                    "port_idx": attrs.get("port_idx"),
                    "poe_enabled": attrs.get("poe_enabled", False),
                    "poe_standard": attrs.get("poe_standard"),
                    "poe_type": attrs.get("poe_type"),
                    "poe_state": attrs.get("poe_state"),
                    "state": attrs.get("state"),
                    "power_priority": "low"  # Default to low priority for power management
                }
                power_map["poe_ports"].append(port_info)
            
            if dry_run:
                return {"status": "plan", "plan": {"action": "power.discover.ports", "expected_effect": f"Map {len(poe_ports)} PoE ports for power management"}}
            return {"status": "ok", "power_map": power_map}
        
        else:
            raise ValueError(f"unsupported target_type for power discovery: {target_type}")