# EUVD API Documentation

[EUVD API doc](https://euvd.enisa.europa.eu/apidoc)

All endpoints are `GET`, require no authentication, no custom headers, and no request body.

Base URL: `https://euvdservices.enisa.europa.eu`

## Frontpage

### Show latest vulnerabilities

| Field          | Value                        |
| -------------- | ---------------------------- |
| Endpoint       | `/api/lastvulnerabilities` |
| Response limit | Maximum 8 records            |

```bash
curl -X GET https://euvdservices.enisa.europa.eu/api/lastvulnerabilities
```

### Show latest exploited vulnerabilities

| Field          | Value                             |
| -------------- | --------------------------------- |
| Endpoint       | `/api/exploitedvulnerabilities` |
| Response limit | Maximum 8 records                 |

```bash
curl -X GET https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities
```

### Show latest critical vulnerabilities

| Field          | Value                            |
| -------------- | -------------------------------- |
| Endpoint       | `/api/criticalvulnerabilities` |
| Response limit | Maximum 8 records                |

```bash
curl -X GET https://euvdservices.enisa.europa.eu/api/criticalvulnerabilities
```

## Scores & Filters

### Query vulnerabilities with flexible filters

| Field          | Value                           |
| -------------- | ------------------------------- |
| Endpoint       | `/api/search`                 |
| Response limit | Maximum 100 records per request |

**Parameters:**

- `fromScore` (0–10, e.g. `fromScore=7.5`)
- `toScore` (0–10, e.g. `toScore=10`)
- `fromEpss` (0–100, e.g. `fromEpss=20`)
- `toEpss` (0–100, e.g. `toEpss=90`)
- `fromDate` (YYYY-MM-DD, e.g. `fromDate=2023-01-14`)
- `toDate` (YYYY-MM-DD, e.g. `toDate=2025-01-14`)
- `fromUpdatedDate` (YYYY-MM-DD, e.g. `fromUpdatedDate=2023-01-14`)
- `toUpdatedDate` (YYYY-MM-DD, e.g. `toUpdatedDate=2025-01-14`)
- `product` (string, e.g. `product=Windows`)
- `vendor` (string, e.g. `vendor=Microsoft`)
- `assigner` (string, e.g. `assigner=mitre`)
- `exploited` (true/false, e.g. `exploited=true`)
- `text` (keywords, e.g. `text=vulnerability`) — searches across description, EUVD ID, aliases, product name, and vendor name.
- `page` (integer, starts at 0, e.g. `page=2`)
- `size` (integer, default 10, e.g. `size=100` — max)

```bash
curl -X GET "https://euvdservices.enisa.europa.eu/api/search?fromScore=0&toScore=10"
```

## Specific Resources

### Show EUVD by ID

| Field    | Value            |
| -------- | ---------------- |
| Endpoint | `/api/enisaid` |

**Parameters:**

- `id` (string, e.g. `id=EUVD-2025-4893`)

```bash
curl -X GET "https://euvdservices.enisa.europa.eu/api/enisaid?id=EUVD-2024-45012"
```

### Show advisory by ID

| Field    | Value             |
| -------- | ----------------- |
| Endpoint | `/api/advisory` |

**Parameters:**

- `id` (string, e.g. `id=oxas-adv-2024-0002`)

```bash
curl -X GET "https://euvdservices.enisa.europa.eu/api/advisory?id=cisco-sa-ata19x-multi-RDTEqRsy"
```

## Data Downloads

### Download CVE-to-EUVD ID Mapping (CSV)

| Field          | Value                                                                                                                                |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Endpoint       | `/api/dump/cve-euvd-mapping`                                                                                                       |
| Response limit | Full dataset (CSV with columns:`euvd_id`, `cve_id`). Contains only records linked to published CVEs. Updated daily at 07:00 UTC. |

```bash
curl -X GET https://euvdservices.enisa.europa.eu/api/dump/cve-euvd-mapping
```

[Download Latest CSV](https://euvdservices.enisa.europa.eu/api/dump/cve-euvd-mapping)

### Download KEV Dump (JSON)

| Field          | Value                                                                                                                                 |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Endpoint       | `/api/kev/dump`                                                                                                                     |
| Response limit | Full dataset (JSON). Consolidated Known Exploited Vulnerabilities from CISA KEV and ENISA EU KEV sources. Updated daily at 07:00 UTC. |

**Response fields:**

- `cveId` — CVE identifier (e.g. `CVE-2021-22555`)
- `euvdId` — EUVD identifier (e.g. `EUVD-2021-9696`)
- `dateAdded` — Earliest date the CVE was added across all KEV sources (format: YYYY-MM-DD)
- `sources` — List of KEV sources that include this CVE (e.g. `cisa_kev`, `eu_kev`)

```bash
curl -X GET https://euvdservices.enisa.europa.eu/api/kev/dump
```

[Download Latest JSON](https://euvdservices.enisa.europa.eu/api/kev/dump)
