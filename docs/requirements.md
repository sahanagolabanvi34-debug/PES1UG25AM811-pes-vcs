# Requirements Table
## Disaster Relief Supply & Volunteer Coordinator
### Scenario No: 64
### Primary Domain: Sustainability & Green Tech

## Functional Requirements

| ID | Type | Description | Priority | Acceptance Criteria | Rationale |
|---|---|---|---|---|---|
| FR-001 | Functional | The system shall match incoming field shelter supply requisitions against available central warehouse supplies and allocate delivery priority. | High | Pass: Critical need given highest dispatch priority and routed to logistics manifest. Fail: Low priority item dispatched ahead of water/medical needs. | Ensures life-critical supplies reach shelters on time. |
| FR-002 | Functional | The system shall allow the Disaster Manager to create and manage shelter supply requisitions including item type, quantity, location, and urgency level. | High | Pass: Request is saved and visible in pending requisitions with correct details. Fail: Request is missing or contains incorrect information. | Accurate requests are essential for proper planning and allocation. |
| FR-003 | Functional | The system shall maintain warehouse inventory of all relief items and update stock when items are allocated or received. | High | Pass: Inventory reflects correct quantities after allocation or receipt. Fail: Stock count is incorrect or not updated. | Real-time inventory prevents shortages and over-allocation. |
| FR-004 | Functional | The system shall assign suitable volunteers to tasks based on skills, availability, and location. | Medium | Pass: Volunteer assigned only if skills and availability match task requirements. Fail: Volunteer without required skills is assigned. | Assigning the right volunteer improves the efficiency of relief operations. |
| FR-005 | Functional | The system shall track relief vehicle deliveries and allow status updates at each stage. | High | Pass: Delivery status is updated successfully and visible on the dashboard. Fail: Status is not updated or an incorrect stage is shown. | End-to-end tracking ensures transparency and accountability. |

## Non-Functional Requirements

| ID | Type | Description | Priority | Acceptance Criteria | Rationale |
|---|---|---|---|---|---|
| NFR-001 | Performance | The disaster mapping dashboard must operate with low network bandwidth consumption and support offline GIS data caching. | High | Pass: Benchmarking tests confirm target latency under simulated peak load and offline maps work correctly. Fail: Dashboard is slow or offline caching fails. | Ensures the system remains usable in disaster areas with poor connectivity. |
| NFR-002 | Security | The system shall ensure that only authorized users can access and perform operations according to their roles. | High | Pass: Unauthorized users cannot access restricted features or data. Fail: Unauthorized access is possible. | Protects sensitive disaster information and prevents misuse. |
