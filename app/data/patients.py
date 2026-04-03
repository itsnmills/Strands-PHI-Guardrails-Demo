"""
app/data/patients.py
────────────────────
Simulated patient database with sensitivity-labeled records.
All data is fictional. No real PHI is processed.

Sensitivity tiers map to HIPAA special categories:
  - STANDARD    : routine clinical data
  - SENSITIVE   : behavioral health, substance use, HIV, reproductive
  - RESTRICTED  : mental health, genetic info — extra access controls
"""

from dataclasses import dataclass, field
from typing import Literal

SensitivityTier = Literal["STANDARD", "SENSITIVE", "RESTRICTED"]


@dataclass
class PatientRecord:
    patient_id: str
    name: str
    dob: str
    mrn: str
    ssn: str
    phone: str
    address: str
    diagnosis: str
    medications: list[str]
    sensitivity: SensitivityTier
    department: str
    notes: str = ""


PATIENT_DB: dict[str, PatientRecord] = {
    "P001": PatientRecord(
        patient_id="P001",
        name="Jane Doe",
        dob="1985-03-14",
        mrn="MRN:4829103",
        ssn="123-45-6789",
        phone="314-555-0101",
        address="42 Maple Street, St. Louis, MO 63101",
        diagnosis="Type 2 Diabetes Mellitus, Chronic Kidney Disease Stage 2",
        medications=["Metformin 500mg BID", "Lisinopril 10mg daily", "Empagliflozin 10mg daily"],
        sensitivity="STANDARD",
        department="Endocrinology",
        notes="Patient enrolled in remote glucose monitoring program.",
    ),
    "P002": PatientRecord(
        patient_id="P002",
        name="John Smith",
        dob="1972-11-22",
        mrn="MRN:7291847",
        ssn="987-65-4321",
        phone="314-555-0202",
        address="17 Oak Avenue, Clayton, MO 63105",
        diagnosis="Hypertension, Hyperlipidemia, Opioid Use Disorder (in remission)",
        medications=["Amlodipine 5mg daily", "Atorvastatin 20mg daily", "Buprenorphine/Naloxone 8mg daily"],
        sensitivity="SENSITIVE",
        department="Internal Medicine",
        notes="Patient participates in substance use recovery program. Extra consent required.",
    ),
    "P003": PatientRecord(
        patient_id="P003",
        name="Sarah Connor",
        dob="1988-07-03",
        mrn="MRN:5519028",
        ssn="456-78-9012",
        phone="636-555-0303",
        address="88 Birch Lane, Ballwin, MO 63021",
        diagnosis="Major Depressive Disorder, Generalized Anxiety Disorder",
        medications=["Sertraline 100mg daily", "Buspirone 15mg BID", "Lorazepam 0.5mg PRN"],
        sensitivity="RESTRICTED",
        department="Behavioral Health",
        notes="Psychiatric records. State law requires separate authorization for disclosure.",
    ),
    "P004": PatientRecord(
        patient_id="P004",
        name="Robert Chen",
        dob="1955-01-30",
        mrn="MRN:8834512",
        ssn="321-54-9876",
        phone="314-555-0404",
        address="5 Elm Drive, Chesterfield, MO 63017",
        diagnosis="Prostate Cancer (Stage II), Hypertension",
        medications=["Leuprolide 22.5mg q3mo", "Amlodipine 10mg daily"],
        sensitivity="STANDARD",
        department="Oncology",
        notes="Patient on hormone therapy. Oncology care team includes radiation oncology.",
    ),
}
