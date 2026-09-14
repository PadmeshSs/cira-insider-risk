# CERT r4.2 Dataset

## 1. Overview

CIRA uses the **CERT Insider Threat Test Dataset, release r4.2** as its primary
dataset for insider-risk behavioural analysis.

CERT r4.2 provides multiple sources of user activity and contextual information
that can be combined to construct behavioural profiles for insider-threat
detection.

The dataset is used throughout the CIRA pipeline beginning with Chapter 3
(Dataset Acquisition & Ingestion), followed by preprocessing, feature
engineering, model training, anomaly scoring, contextual risk analysis, and
evaluation.

CERT is the primary dataset for the project, while TWOS is designated as the
secondary dataset.

---

## 2. Dataset Role in CIRA

CERT r4.2 is used as the primary experimental dataset because it contains
multiple complementary sources of enterprise-user activity and contextual
information.

The CIRA ingestion layer converts the raw CERT records into a common canonical
event representation.

The overall data flow is:

```text
CERT r4.2 Raw Dataset
        |
        v
CERT Ingestion Loader
        |
        v
Canonical Event Contract
        |
        v
Chapter 4 - Preprocessing
        |
        v
Chapter 5 - Feature Engineering
        |
        v
Behavioural Feature Matrix
        |
        v
Models / Anomaly Detection
        |
        v
Evaluation
```

---

## 3. Dataset Acquisition

CERT r4.2 is obtained from Carnegie Mellon's KiltHub repository.

The project implementation documentation identifies the KiltHub dataset
repository and DOI as:

```text
DOI: 10.1184/R1/12841247.v1
```

The KiltHub repository contains multiple CERT releases together with the
associated ground-truth answers archive.

Only the r4.2 release is required for the current CIRA implementation.

The project must not unnecessarily extract or process other CERT releases.

---

## 4. Local Storage

The raw CERT dataset is stored outside the Git repository because of its large
size.

Current local development path:

```text
D:\CIRA_dataset\datasets\raw\cert_r4.2\
```

The physical path is environment-specific.

The ingestion loader accepts the dataset root as a runtime argument, so the
implementation is not dependent on this particular Windows path.

Example:

```powershell
python scripts\cert_smoke_test.py `
    --root D:\CIRA_dataset\datasets\raw\cert_r4.2 `
    --rows 10
```

---

## 5. Raw Dataset Structure

The verified CERT r4.2 directory contains the following behavioural data files:

```text
cert_r4.2/
├── logon.csv
├── device.csv
├── email.csv
├── file.csv
├── http.csv
├── psychometric.csv
│
└── LDAP/
    ├── 2009-12.csv
    ├── 2010-01.csv
    ├── 2010-02.csv
    ├── 2010-03.csv
    ├── 2010-04.csv
    ├── 2010-05.csv
    ├── 2010-06.csv
    ├── 2010-07.csv
    ├── 2010-08.csv
    ├── 2010-09.csv
    ├── 2010-10.csv
    ├── 2010-11.csv
    ├── 2010-12.csv
    ├── 2011-01.csv
    ├── 2011-02.csv
    ├── 2011-03.csv
    ├── 2011-04.csv
    └── 2011-05.csv
```

The current extracted dataset has been verified to contain 18 LDAP monthly
snapshots.

---

## 6. CERT Data Domains

The CIRA ingestion layer handles the following CERT domains:

- Logon
- Device
- Email
- File
- HTTP
- Psychometric
- LDAP

Each domain is read independently and converted into the canonical CIRA event
contract.

---

## 7. Logon Data

Source file:

```text
logon.csv
```

Verified schema:

```text
id
date
user
pc
activity
```

The logon domain represents user authentication-related activity.

The CIRA loader maps:

| Source column | Canonical field         |
|---------------|-------------------------|
| `id`          | source record identifier |
| `date`        | `timestamp`             |
| `user`        | `user_id`               |
| `pc`          | `device_id`             |
| `activity`    | event activity          |

The remaining source attributes are preserved inside the canonical event's
`details` field.

---

## 8. Device Data

Source file:

```text
device.csv
```

Verified schema:

```text
id
date
user
pc
activity
```

Device records provide information about user interaction with devices and
removable media.

The CIRA loader maps the common identifiers and timestamp into the canonical
representation while preserving the original source attributes.

---

## 9. Email Data

Source file:

```text
email.csv
```

Verified schema:

```text
id
date
user
pc
to
cc
bcc
from
size
attachments
content
```

Email records provide communication-related behavioural information.

The raw email attributes are preserved in the canonical event's `details` field.

Potential downstream feature-engineering uses include:

- email activity frequency;
- recipient behaviour;
- attachment activity;
- message size;
- internal/external communication patterns.

Feature engineering is not performed by the Chapter 3 ingestion layer.

---

## 10. File Data

Source file:

```text
file.csv
```

Verified schema:

```text
id
date
user
pc
filename
content
```

File activity provides information about user interaction with files and
file-system resources.

The loader preserves the original filename and content attributes inside the
canonical event.

Later chapters may derive behavioural features from file activity.

---

## 11. HTTP Data

Source file:

```text
http.csv
```

Verified schema:

```text
id
date
user
pc
url
content
```

HTTP records represent web/network-related user activity.

The original URL and content attributes remain available inside the canonical
event's `details` field.

The Chapter 3 loader does not attempt to determine whether a URL is malicious or
benign. Such interpretation belongs to later analytical stages.

---

## 12. Psychometric Data

Source file:

```text
psychometric.csv
```

Verified schema:

```text
employee_name
user_id
O
C
E
A
N
```

The psychometric data provides personality-related contextual attributes.

The five dimensions represented by the source are retained as raw attributes.

These values are contextual information and are not ground-truth insider-threat
labels.

The Chapter 3 loader preserves these source attributes without turning them into
threat decisions.

---

## 13. LDAP Data

LDAP data is stored under:

```text
LDAP/
```

The verified release contains 18 monthly snapshots:

```text
2009-12.csv
2010-01.csv
2010-02.csv
2010-03.csv
2010-04.csv
2010-05.csv
2010-06.csv
2010-07.csv
2010-08.csv
2010-09.csv
2010-10.csv
2010-11.csv
2010-12.csv
2011-01.csv
2011-02.csv
2011-03.csv
2011-04.csv
2011-05.csv
```

Verified LDAP schema:

```text
employee_name
user_id
email
role
business_unit
functional_unit
department
team
supervisor
```

LDAP provides organizational context that can later support peer-group and
contextual features. For example, later feature engineering can use role or
department information where appropriate.

The Chapter 3 loader represents LDAP records as:

```text
source_type = ldap
event_type  = ldap_snapshot
```

LDAP snapshots do not contain a behavioural timestamp in the current canonical
representation.

The source snapshot filename is preserved in the event metadata.

Example:

```text
LDAP\2009-12.csv
```

---

## 14. Canonical Event Contract

The CIRA ingestion architecture converts source-specific records into a shared
canonical representation.

The canonical event contains:

```text
event_id
timestamp
user_id
device_id
source_type
event_type
details
metadata
```

The implementation is defined in:

```text
backend/app/ingestion/contracts.py
```

The CERT-specific loader is:

```text
backend/app/ingestion/cert_loader.py
```

---

## 15. Event Identifier

Each canonical event receives a stable `event_id`.

Where the source dataset provides an identifier, the loader uses the source
identifier as part of the canonical event identity.

When a source identifier is unavailable, the loader generates a deterministic
identifier using the source information and row context.

This provides reproducibility while retaining traceability to the raw dataset.

---

## 16. Source Traceability

Source provenance is preserved in the canonical event's `metadata`.

The metadata includes:

```text
dataset
release
domain
source_file
source_row_number
```

When a source record ID exists, the loader also records:

```text
source_record_id
```

Example:

```json
{
    "dataset": "CERT",
    "release": "r4.2",
    "domain": "logon",
    "source_file": "logon.csv",
    "source_row_number": 1,
    "source_record_id": "1"
}
```

This allows downstream records to be traced back to their original CERT source.

---

## 17. Source-Specific Attributes

The CIRA canonical contract intentionally does not attempt to flatten every
possible source-specific attribute into top-level fields.

Source-specific values remain under:

```text
details
```

For example, an LDAP event may contain:

```json
{
    "employee_name": "Calvin Edan Love",
    "user_id": "CEL0561",
    "email": "Calvin.Edan.Love@dtaa.com",
    "role": "ComputerProgrammer",
    "business_unit": 1,
    "functional_unit": "2 - ResearchAndEngineering",
    "department": "2 - SoftwareManagement",
    "team": "3 - Software",
    "supervisor": "Stephanie Briar Harrington"
}
```

This preserves information required by later processing stages.

---

## 18. Ground-Truth Separation

CERT ground truth is kept completely separate from behavioural event ingestion.

The ground-truth answers archive is used for:

- evaluation;
- detection-performance measurement;
- supervised baseline experiments where explicitly required.

It must not be used as an input to the unsupervised behavioural feature
pipeline.

Ground-truth information must not be copied into:

```text
CanonicalEvent.details
CanonicalEvent.metadata
feature vectors
unsupervised model-training input
```

This separation prevents target leakage.

---

## 19. Ground-Truth Loader

Ground-truth handling is implemented separately from the behavioural CERT
loader.

The implementation is located at:

```text
backend/app/ingestion/ground_truth.py
```

The ground-truth module is not called by the normal behavioural event-ingestion
path.

This creates a clear architectural boundary:

```text
Raw CERT Behavioural Data
          |
          v
    cert_loader.py
          |
          v
 Canonical Events
          |
          v
 Preprocessing / Features
```

while ground truth follows a separate path:

```text
CERT Ground Truth
       |
       v
ground_truth.py
       |
       v
Evaluation
```

---

## 20. Data Leakage Prevention

The CERT loader explicitly rejects obvious ground-truth columns if they appear
in behavioural input.

Examples include:

```text
label
labels
insider
malicious
is_malicious
ground_truth
scenario
```

If such fields are detected in a behavioural CSV, the loader raises an explicit
error rather than silently allowing potential leakage.

This is a defensive measure.

The actual CERT answer data remains in the separate ground-truth location.

---

## 21. Large-File Processing

CERT r4.2 is large enough that the loader must not assume that every CSV can
safely be loaded into memory at once.

The CERT loader therefore processes behavioural CSV files in chunks.

The default chunk size is:

```text
10,000 rows
```

This allows the ingestion implementation to operate on large raw files without
requiring the entire file to be loaded into memory.

---

## 22. Ingestion Module

Primary loader:

```text
backend/app/ingestion/cert_loader.py
```

Canonical contract:

```text
backend/app/ingestion/contracts.py
```

Ground-truth loader:

```text
backend/app/ingestion/ground_truth.py
```

Unit tests:

```text
backend/tests/unit/test_cert_loader.py
backend/tests/unit/test_ground_truth_separation.py
```

Validation scripts:

```text
scripts/cert_smoke_test.py
scripts/cert_inventory.py
```

---

## 23. Header Inspection

The loader provides header inspection for the real CERT dataset.

Example:

```powershell
python -c "from backend.app.ingestion.cert_loader import inspect_csv_headers; import pprint; pprint.pp(inspect_csv_headers(r'D:\CIRA_dataset\datasets\raw\cert_r4.2'))"
```

This verifies that the expected source files can be located and that their
headers do not contain prohibited ground-truth columns.

---

## 24. Smoke Testing

The CERT smoke test loads a small number of records from every domain and
verifies canonical-schema conformance.

Example:

```powershell
python scripts\cert_smoke_test.py `
    --root D:\CIRA_dataset\datasets\raw\cert_r4.2 `
    --rows 10
```

The smoke test verifies:

- each behavioural domain can be read;
- LDAP snapshots can be read;
- records become canonical events;
- canonical identifiers exist;
- source metadata exists;
- source traceability exists;
- ground-truth fields are absent from canonical events.

---

## 25. Dataset Inventory

The inventory utility counts records in the raw CERT files.

Example:

```powershell
python scripts\cert_inventory.py `
    --root D:\CIRA_dataset\datasets\raw\cert_r4.2
```

The inventory should report separate counts for:

```text
logon
device
email
file
http
psychometric
LDAP
```

LDAP rows are reported separately because LDAP represents organizational
snapshots rather than behavioural events.

The inventory output is the authoritative count for the local dataset used in
the implementation run.

Published or previously reported counts must not be substituted for actual
local verification.

---

## 26. Reproducibility

The raw CERT dataset is intentionally excluded from source control.

The source repository contains:

- ingestion code;
- tests;
- validation scripts;
- documentation.

The dataset itself remains in local storage.

A reproduction environment must obtain the appropriate CERT release and supply
its root directory to the ingestion scripts.

---

## 27. Chapter 3 Acceptance Criteria

CERT ingestion is considered accepted only when the following have been
verified:

- [ ] CERT r4.2 has been obtained and extracted.
- [ ] The expected CERT domain structure exists.
- [ ] All six behavioural domains can be loaded.
- [ ] LDAP snapshots can be loaded.
- [ ] The canonical event contract validates successfully.
- [ ] Source traceability is preserved.
- [ ] Real-data smoke testing passes.
- [ ] Dataset inventory has been executed against the actual local release.
- [ ] Ground truth remains separate from behavioural events.
- [ ] Unit tests pass.
- [ ] No fabricated CERT counts or experimental results are used.

The Implementation Bible specifies that CERT r4.2 should match the known release
structure and approximately 32.77 million behavioural events, with 7,323
malicious instances in the released ground truth; the local inventory is still
required to verify the actual files used by this project.

---

## 28. Relationship to Later Chapters

Chapter 3 produces the raw canonical event stream required by Chapter 4.

Chapter 4 performs:

- timestamp normalization;
- identifier normalization;
- missing-value handling;
- malformed-record handling;
- categorical normalization;
- schema validation.

Chapter 5 then builds the behavioural feature matrix.

Therefore, Chapter 3 should remain focused on acquisition, parsing,
canonicalization, traceability, and leakage prevention.

Feature engineering and threat detection do not belong in the CERT ingestion
layer.