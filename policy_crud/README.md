# Policy Configuration CRUD - Installation Guide

## Files Overview

1. **get_policy_service.py** - Service untuk membaca policy configuration
2. **update_policy_service.py** - Service untuk update policy configuration
3. **policy_controller.py** - Controller untuk handle HTTP requests
4. **policy.html** - Template HTML untuk UI
5. **admin.py** - Router yang sudah diupdate dengan policy endpoints
6. **sidebar.html** - Sidebar yang sudah ditambahkan menu Policy

## Installation Steps

### 1. Copy Service Files
```bash
cp get_policy_service.py app/services/policy/
cp update_policy_service.py app/services/policy/
```

### 2. Copy Controller File
```bash
cp policy_controller.py app/controllers/admin/
```

### 3. Copy Template File
```bash
cp policy.html app/web/templates/admin/
```

### 4. Replace Router and Sidebar
```bash
cp admin.py app/web/routers/
cp sidebar.html app/web/templates/admin/partials/
```

### 5. Create Services Directory (if not exists)
```bash
mkdir -p app/services/policy
touch app/services/policy/__init__.py
```

## Features

### 1. Network Segments Management
- Add/Edit/Delete network segments
- Configure block and monitor thresholds per segment
- Map subnets to segments (CIDR format)

### 2. Feature Weights Configuration
- DNS Weight (default: 40)
- SNI Weight (default: 35)
- ASN Weight (default: 15)
- Burst Weight (default: 10)
- Total must equal 100

### 3. Burst Detection Settings
- DNS Queries per Minute (Monitor)
- DNS Queries per Minute (Block)

### 4. Enforcement Configuration
- IPSet Name (IPv4)
- IP Timeout (seconds)
- NFTables Table
- NFTables Chain

### 5. Data Collectors Configuration
- DNSmasq log path
- Zeek SSL log path
- Enable/Disable Zeek SNI collection

## API Endpoints

### GET Endpoints
- `GET /admin/policy` - Display policy configuration page

### POST Endpoints
- `POST /admin/policy/segment` - Add/Update segment
- `POST /admin/policy/segment/subnets` - Update segment subnets
- `POST /admin/policy/features` - Update feature weights
- `POST /admin/policy/enforcement` - Update enforcement settings
- `POST /admin/policy/collectors` - Update collectors settings
- `POST /admin/policy/burst` - Update burst detection settings

### DELETE Endpoints
- `DELETE /admin/policy/segment/{segment_name}` - Delete segment

## Request/Response Examples

### Add/Update Segment
```bash
curl -X POST http://localhost:8000/admin/policy/segment \
  -H "Content-Type: application/json" \
  -d '{
    "segment_name": "student",
    "block_threshold": 60,
    "monitor_threshold": 40
  }'
```

### Update Segment Subnets
```bash
curl -X POST http://localhost:8000/admin/policy/segment/subnets \
  -H "Content-Type: application/json" \
  -d '{
    "segment_name": "student",
    "subnets": ["10.10.0.0/16", "192.168.1.0/24"]
  }'
```

### Update Feature Weights
```bash
curl -X POST http://localhost:8000/admin/policy/features \
  -H "Content-Type: application/json" \
  -d '{
    "dns_weight": 40,
    "sni_weight": 35,
    "asn_weight": 15,
    "burst_weight": 10
  }'
```

### Delete Segment
```bash
curl -X DELETE http://localhost:8000/admin/policy/segment/student
```

## Validation Rules

### Segments
- Segment name cannot be empty
- Block threshold: 0-100
- Monitor threshold: 0-100
- Monitor threshold must be less than block threshold
- Cannot delete "default" segment

### Subnets
- Must be valid CIDR format (e.g., 10.10.0.0/16)
- Segment must exist before adding subnets

### Feature Weights
- Each weight: 0-100
- Total must equal 100

### Burst Detection
- Both values must be non-negative
- Monitor threshold must be less than block threshold

## Backup System

The system automatically creates backups before any policy update:
- Backup filename format: `policy.json.backup.YYYYMMDD_HHMMSS`
- Stored in the same directory as policy.json
- Example: `policy.json.backup.20250119_143022`

## Access

After installation, access the policy configuration at:
```
http://your-server:8000/admin/policy
```

## Security Notes

1. All routes are protected by authentication middleware
2. Input validation on all endpoints
3. Automatic backup before any changes
4. Cannot delete default segment
5. Validates CIDR format for subnets

## Troubleshooting

### Policy file not found
- Check MINIFW_POLICY environment variable
- Default location: `config/policy.json`

### Invalid JSON error
- Check policy.json syntax
- Restore from backup if needed

### Segment not found
- Verify segment exists in segments section
- Create segment before adding subnets

### Weights don't sum to 100
- Adjust weights to total exactly 100
- UI will show error if sum ≠ 100
