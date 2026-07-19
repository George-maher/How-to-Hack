# API Documentation

## Base URL

```
http://localhost:8000/api
```

## Endpoints

### Projects

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/projects` | List all projects |
| POST | `/projects` | Create a new project |
| GET | `/projects/{id}` | Get project details |
| PUT | `/projects/{id}` | Update a project |
| DELETE | `/projects/{id}` | Delete a project |
| POST | `/projects/{id}/scan` | Initiate a scan |

**POST `/projects`**
```json
{
  "name": "My Project",
  "target_url": "https://example.com",
  "description": "Optional description"
}
```

**POST `/projects/{id}/scan`**
Returns `202 Accepted` with:
```json
{
  "message": "Scan initiated",
  "scan_id": 1
}
```

### Scans

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/projects/{projectId}/scans` | List scans for a project |
| GET | `/scans/{scanId}` | Get scan details with results |
| POST | `/scans/{scanId}/cancel` | Cancel a scan |

### Scan Results

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/scans/{scanId}/results` | List all results for a scan |
| GET | `/scans/{scanId}/results/severity` | Get severity breakdown |

### Scanners

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/scanners` | List all registered scanners |

## Error Responses

```json
{
  "message": "Error description"
}
```

Status codes:
- `200` - Success
- `201` - Created
- `202` - Accepted (async operation)
- `400` - Bad request
- `404` - Not found
