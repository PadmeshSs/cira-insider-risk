# TWOS Secondary Dataset

## 1. Overview

TWOS is designated as the **secondary dataset** for CIRA.

The purpose of using a secondary dataset is to provide an additional data source
through which the CIRA ingestion architecture and, where supported by the
released data, downstream analytics can be assessed.

CERT r4.2 remains the primary dataset for the project.

TWOS is handled independently because access to the dataset requires a
release/access process and the exact schema must be verified from the authorised
dataset release.

---

## 2. Dataset Role in CIRA

The intended role of TWOS is:

```text
TWOS Raw Dataset
        |
        v
TWOS Ingestion Loader
        |
        v
Canonical Event Contract
        |
        v
Shared CIRA Processing Pipeline
```

The use of a canonical event contract allows the ingestion layer to abstract
dataset-specific differences before the common preprocessing and analytics
stages.

However, TWOS-specific mappings must only be finalized after the actual
authorised release has been received and its schema inspected.

---

## 3. Current Acquisition Status

Current project status:

```text
PLANNED
```

This status means that TWOS has been designated as a secondary dataset but the
project must not claim that the dataset has been successfully acquired until the
authorised release is actually in hand.

The status may later become:

```text
IN-PROGRESS
```

when the formal access/release process has started.

It may become:

```text
AVAILABLE
```

only after the actual dataset files have been received and are available for
local processing.

---

## 4. Acquisition Process

According to the CIRA implementation plan, TWOS access is not treated as an
instant public download.

The planned process is:

```text
Identify TWOS release
        |
        v
Review release requirements
        |
        v
Complete required release agreement
        |
        v
Submit access request
        |
        v
Supervisor confirmation
        |
        v
Receive authorised dataset
        |
        v
Inspect actual schema
        |
        v
Validate ingestion
```

The access process should be started early rather than delaying it until the
ingestion chapter.

The project must not represent TWOS access as complete without evidence that the
dataset has actually been received.

---

## 5. No Fabricated TWOS Data

The project must never create fabricated TWOS records merely to make the
secondary-dataset component appear complete.

The following must not be fabricated:

- TWOS events;
- TWOS row counts;
- TWOS labels;
- TWOS evaluation metrics;
- TWOS schema details;
- TWOS acquisition status.

If the dataset is unavailable, the correct project status remains `PLANNED` or
`IN-PROGRESS`, depending on the actual access state.

---

## 6. Local Storage

Once the authorised TWOS dataset is received, the recommended local directory
is:

```text
D:\CIRA_dataset\datasets\raw\twos\
```

The actual local path may differ.

The TWOS loader accepts the dataset root as a runtime parameter.

The raw TWOS dataset should not be committed to Git unless its licensing and
redistribution terms explicitly permit doing so.

---

## 7. Ingestion Module

TWOS ingestion is implemented through:

```text
backend/app/ingestion/twos_loader.py
```

The loader is designed to:

- detect whether TWOS data is physically available;
- discover supported data files;
- inspect the actual schema;
- reject obvious ground-truth leakage;
- convert available records into the CIRA canonical event contract;
- preserve source traceability;
- support small-sample validation.

---

## 8. Schema Policy

The exact TWOS schema must be determined from the authorised release.

The project deliberately does not claim a fixed TWOS schema before the actual
files have been received and inspected.

After receiving the release, the first step is schema inspection.

The loader provides:

```text
inspect_twos_headers(...)
```

Example:

```python
from backend.app.ingestion.twos_loader import (
    inspect_twos_headers,
)

headers = inspect_twos_headers(
    r"D:\CIRA_dataset\datasets\raw\twos"
)

print(headers)
```

The resulting schema should be reviewed before finalizing any dataset-specific
mappings.

---

## 9. Supported Source Formats

The current TWOS loader is designed to recognize:

```text
.csv
.parquet
```

This does not imply that the TWOS release necessarily uses either format.

The actual release format must be verified when the dataset becomes available.

Unsupported formats should not be silently interpreted.

---

## 10. Canonical Event Contract

Where TWOS records are available, they are converted into the same CIRA
canonical event contract used by CERT.

The contract contains:

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

The shared contract is defined in:

```text
backend/app/ingestion/contracts.py
```

---

## 11. TWOS Source Attributes

Dataset-specific TWOS attributes remain under:

```text
details
```

rather than being discarded.

This preserves the original information required for downstream processing while
maintaining a common canonical interface.

The exact mapping between TWOS source columns and canonical fields must be
verified after the actual dataset is received.

---

## 12. Source Traceability

TWOS canonical events preserve source provenance.

Metadata includes:

```text
dataset
source_file
source_row_number
```

When a source record identifier is available, the loader also preserves:

```text
source_record_id
```

This allows downstream processing to trace a canonical event back to its
original TWOS record.

---

## 13. Event Identification

The TWOS loader uses a source identifier when one is available.

When no source identifier exists, the loader creates a deterministic identifier
from:

- source file;
- source row;
- source record contents.

The purpose is reproducibility and source traceability.

---

## 14. Timestamp Handling

If the TWOS source contains a recognizable timestamp field, the loader attempts
to parse it into the canonical timestamp field.

If the source does not contain a timestamp, the loader does not invent one.

Timestamp normalization and timezone policy belong to the Chapter 4
preprocessing stage.

---

## 15. User and Device Identification

The TWOS loader supports common user and device identifier aliases where they
can be detected from the actual source schema.

Potential user aliases include:

```text
user
user_id
userid
employee
employee_id
```

Potential device aliases include:

```text
device
device_id
deviceid
pc
computer
```

These mappings are generic defensive mappings.

They must be validated against the actual TWOS release before the TWOS ingestion
component is considered fully accepted.

---

## 16. Event Type

If the actual TWOS dataset provides an activity or event field, the loader can
use that information to construct the canonical `event_type`.

If such a field is unavailable, the loader uses a generic TWOS event type rather
than inventing semantics.

Dataset-specific semantic interpretation belongs in later processing stages.

---

## 17. Ground-Truth Separation

TWOS ground truth, if supplied separately by the dataset release, must remain
separate from the behavioural event stream.

Ground-truth information must not be copied into:

```text
CanonicalEvent.details
CanonicalEvent.metadata
feature vectors
unsupervised model input
```

The same data-leakage principle used for CERT applies to TWOS.

---

## 18. Ground-Truth Columns

The TWOS loader defensively rejects obvious target/ground-truth columns such as:

```text
label
labels
insider
malicious
is_malicious
ground_truth
groundtruth
target
```

If such columns are detected in the behavioural input, ingestion fails
explicitly rather than allowing potential target leakage.

The exact TWOS ground-truth format must be inspected separately if the
authorised release provides one.

---

## 19. Dataset Availability Detection

The TWOS loader provides:

```text
twos_available(...)
```

This reports whether supported TWOS files are physically present under the
supplied directory.

It also provides:

```text
get_twos_status(...)
```

which distinguishes an unavailable local dataset from an available one.

Filesystem availability does not itself prove that the data is legally
authorised for use.

The acquisition status must therefore remain consistent with the actual project
documentation.

---

## 20. Behaviour When TWOS Is Unavailable

When the TWOS directory contains no supported data files, the loader fails
explicitly.

Example:

```text
TWOS dataset unavailable
        |
        v
FileNotFoundError
```

The loader must not:

- generate fake data;
- generate placeholder events;
- generate fake labels;
- generate fake row counts.

This ensures that missing TWOS access cannot silently turn into fabricated
experimental evidence.

---

## 21. TWOS Sample Validation

Once the actual dataset is received, a small sample can be loaded using:

```python
from backend.app.ingestion.twos_loader import (
    load_twos_sample,
)

events = load_twos_sample(
    r"D:\CIRA_dataset\datasets\raw\twos",
    rows=10,
)

for event in events:
    print(event.model_dump_json(indent=2))
```

The sample should be used to verify:

- records can be parsed;
- canonical fields are populated where supported;
- source traceability is preserved;
- source-specific fields remain available;
- ground-truth leakage is absent.

---

## 22. Header Inspection

Before implementing final TWOS mappings, inspect the actual source headers.

Example:

```python
from backend.app.ingestion.twos_loader import (
    inspect_twos_headers,
)

headers = inspect_twos_headers(
    r"D:\CIRA_dataset\datasets\raw\twos"
)

for filename, columns in headers.items():
    print(filename)
    print(columns)
```

The observed schema should then be documented in this file.

Until that verification occurs, this document intentionally does not claim a
specific TWOS schema.

---

## 23. Relationship to CERT

CERT and TWOS have different roles:

| Dataset   | Role      | Current status |
|-----------|-----------|----------------|
| CERT r4.2 | Primary   | Available      |
| TWOS      | Secondary | Planned        |

CERT is the primary dataset used to validate the core Chapter 3 ingestion
implementation.

TWOS is intended to use the same canonical event boundary once its authorised
data and schema are available.

---

## 24. Shared Architecture

The intended architecture is:

```text
                  +----------------------+
                  |     CERT r4.2        |
                  |    Primary Dataset   |
                  +----------+-----------+
                             |
                             v
                    cert_loader.py
                             |
                             |
                             v
                    Canonical Events
                             ^
                             |
                             |
                    twos_loader.py
                             |
                             ^
                  +----------+-----------+
                  |       TWOS           |
                  |  Secondary Dataset   |
                  +----------------------+
```

Both loaders target:

```text
backend/app/ingestion/contracts.py
```

This provides a consistent boundary for later preprocessing.

---

## 25. Chapter 3 Status

Current TWOS status:

```text
PLANNED
```

This status is intentional.

TWOS should be changed to `IN-PROGRESS` only when the project has actually begun
the access/release process.

TWOS should be changed to `AVAILABLE` only after the authorised dataset has
actually been received.

The implementation status must not be upgraded merely because `twos_loader.py`
exists.

---

## 26. Acceptance Criteria

TWOS ingestion is accepted only after the following have been verified:

- [ ] Required TWOS access/release process has been initiated.
- [ ] The authorised TWOS dataset has actually been received.
- [ ] The raw files are stored locally.
- [ ] The actual TWOS schema has been inspected.
- [ ] Dataset-specific mappings have been validated.
- [ ] Records can be converted into `CanonicalEvent`.
- [ ] Source traceability is preserved.
- [ ] Ground truth remains separate.
- [ ] A real-data TWOS sample passes ingestion validation.
- [ ] No TWOS results or counts have been fabricated.

Until these conditions are met, TWOS remains a secondary dataset with status
`PLANNED` or `IN-PROGRESS`.

---

## 27. Relationship to Later Chapters

Once TWOS is available and validated, its canonical events can enter the same
general downstream processing boundary as CERT:

```text
TWOS Raw Data
     |
     v
TWOS Loader
     |
     v
Canonical Events
     |
     v
Chapter 4
Preprocessing
     |
     v
Chapter 5
Feature Engineering
```

However, dataset-specific differences must be documented rather than silently
assuming that CERT and TWOS contain identical fields.

---

## 28. Reproducibility

The TWOS raw dataset should remain outside source control unless its license
explicitly permits redistribution.

The repository contains the ingestion implementation and documentation required
to process the authorised release.

The actual TWOS dataset must be obtained according to its applicable release
conditions.

---

## 29. Non-Fabrication Rule

The project follows the following rule for TWOS:

> No dataset access, schema, row count, label count, model result, or evaluation
> result is claimed unless it has been directly verified from the actual
> authorised TWOS release.

This is particularly important because TWOS is a secondary dataset and its
availability is dependent on the release process.

CERT remains the primary verified dataset until TWOS becomes actually available.