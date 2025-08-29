# UniFi Network Integration Plugin

A comprehensive integration plugin for UniFi Network controllers, providing device management, client access control, and voucher lifecycle capabilities through the UniFi Network Integration API (v9.4.x).

## Features

- **Device Management**: List, monitor, and restart UniFi devices
- **Port Control**: Power-cycle specific ports on UniFi devices  
- **Client Access**: Authorize/unauthorize guest access with configurable limits
- **Voucher Lifecycle**: Generate and manage hotspot vouchers
- **Site Inventory**: List and filter sites, devices, clients, and vouchers
- **Application Info**: Retrieve UniFi Network controller version and status

## Configuration

### Connection Settings

```yaml
connection:
  hostname: "10.0.0.1"                    # Controller IP or FQDN
  api_key: "your-integration-api-key"       # UniFi Integrations API Key
  verify_ssl: true                          # SSL certificate verification
  base_path: "/proxy/network/integration/v1" # API base path
  
  # Authentication header configuration (auto-detects if not specified)
  auth_header_name: "Authorization"         # Header name for API key
  auth_scheme: "Bearer"                     # Authentication scheme
```

### Authentication

The plugin supports flexible authentication header configuration:

- **Default**: `Authorization: Bearer <api_key>` 
- **X-API-Key**: Set `auth_header_name: "X-API-Key"` and `auth_scheme: ""`
- **Custom**: Configure any header name/scheme combination

If authentication fails with default settings, the plugin automatically tries common alternatives (`X-API-Key`, `X-Auth-Token`).

## Capabilities

### Inventory Management (`inventory.list`)

List and filter resources across your UniFi network:

```python
# List all sites
sites = driver.inventory_list("site")

# List devices in a specific site
devices = driver.inventory_list("device", options={"site_id": "site123"})

# List clients with filtering
clients = driver.inventory_list("client", options={
    "site_id": "site123",
    "filter": "eq(connected,true)"
})

# List vouchers with filtering
vouchers = driver.inventory_list("voucher", options={
    "site_id": "site123", 
    "filter": "eq(status,ACTIVE)"
})
```

**Supported Targets**: `site`, `device`, `client`, `voucher`

### Application Info (`unifi.application.info`)

Get controller version and status information:

```python
info = driver.unifi_application_info("get", {})
# Returns: {"status": "ok", "info": {"applicationVersion": "9.4.x"}}
```

### Device Lifecycle (`unifi.device.lifecycle`)

Restart UniFi devices:

```python
# Dry run - preview the action
plan = driver.unifi_device_lifecycle("restart", 
    {"site_id": "site123"}, 
    dry_run=True, 
    device_id="device456"
)

# Execute restart
result = driver.unifi_device_lifecycle("restart", 
    {"site_id": "site123"}, 
    device_id="device456"
)
```

### Port Lifecycle (`unifi.port.lifecycle`) 

Power-cycle specific ports on devices:

```python
# Power-cycle port 8 on a switch
result = driver.unifi_port_lifecycle("power-cycle", 
    {"site_id": "site123"}, 
    device_id="switch789", 
    port_idx=8
)
```

### Client Access Control (`unifi.client.access`)

Manage guest access authorization with optional limits:

```python
# Authorize guest with time and data limits
result = driver.unifi_client_access("authorize-guest", 
    {"site_id": "site123"}, 
    client_id="client123",
    time_limit_minutes=240,
    data_usage_limit_mbytes=1000,
    rx_rate_limit_kbps=10000,
    tx_rate_limit_kbps=5000
)

# Unauthorize guest access  
result = driver.unifi_client_access("unauthorize-guest",
    {"site_id": "site123"},
    client_id="client123"
)
```

**Supported Verbs**: `authorize-guest`, `unauthorize-guest` (invertible)

### Voucher Management (`unifi.voucher.lifecycle`)

Generate and delete hotspot vouchers:

```python
# Generate vouchers
result = driver.unifi_voucher_lifecycle("generate",
    {"site_id": "site123"},
    count=5,
    name="Conference-2024",
    authorized_guest_limit=1,
    time_limit_minutes=480,
    data_usage_limit_mbytes=2000
)

# Delete specific voucher
result = driver.unifi_voucher_lifecycle("delete",
    {"site_id": "site123", "id": "voucher789"}
)

# Delete vouchers by filter
result = driver.unifi_voucher_lifecycle("delete",
    {"site_id": "site123"},
    filter="eq(status,EXPIRED)"
)
```

## API Integration Details

- **Base URL**: `https://{hostname}/proxy/network/integration/v1`
- **Authentication**: Configurable API key authentication
- **Rate Limiting**: Automatic exponential backoff with Retry-After support
- **Pagination**: Automatic handling of offset/limit pagination
- **Error Handling**: Comprehensive error responses with UniFi status codes

### Filtering Syntax

The UniFi API supports advanced filtering for clients and vouchers:

- `eq(field,value)` - equals
- `ne(field,value)` - not equals  
- `gt(field,value)` - greater than
- `like(field,pattern)` - pattern matching
- `in(field,[value1,value2])` - value in list
- `notIn(field,[value1,value2])` - value not in list

## Rate Limiting & Reliability

- **Retry Strategy**: Exponential backoff for transient failures (5 total, 3 connect retries)
- **Status Codes**: Handles 429, 500, 502, 503, 504 with automatic retry
- **Retry-After**: Respects server-provided retry delays (capped at 10s)
- **Timeout**: 30-second request timeout for all operations

## Requirements

- Python 3.12+
- UniFi Network Controller 9.4.x+
- Integration API access enabled
- Valid Integration API key

## Testing Connection

Use the application info endpoint to validate your configuration:

```python
# Test basic connectivity and authentication
status = driver.test_connection()
print(status)  # {"status": "connected", "latency_ms": 45, "details": "UniFi Network 9.4.56"}
```

## Framework Compliance

This plugin follows the Walut framework specification:

- **Dry Run Support**: All mutating operations support dry-run mode with detailed execution plans
- **Idempotency**: Operations are idempotent based on target and parameter combinations
- **Invertible Actions**: Client access operations are reversible
- **Consistent Naming**: kebab-case verbs, snake_case targets
- **Error Handling**: Standardized error responses and status codes

## License

This plugin is provided as-is for integration with UniFi Network controllers via the official Integration API.