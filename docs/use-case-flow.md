# Use-Case Flow Specification

## Use Case ID
UC-01

## Use Case Name
Allocate Relief Supplies

## Primary Actor
Disaster Manager

## Goal
Allocate required relief supplies from the warehouse to a shelter request and create a delivery entry.

## Preconditions
1. Disaster Manager is logged in.
2. At least one shelter supply request exists.
3. Warehouse inventory information is available.

## Postconditions
1. Supplies are allocated to the request.
2. Delivery priority is set and recorded.
3. Delivery entry is created in the logistics manifest.

## Main Success Scenario

1. Disaster Manager opens the list of pending shelter supply requests.
2. System displays the request details including items, quantity, location, and urgency.
3. Disaster Manager selects a request to allocate supplies.
4. System checks available stock in the warehouse.
5. System matches requested items with available stock.
6. System calculates delivery priority based on urgency and item type.
7. Disaster Manager reviews the allocation and confirms.
8. System allocates the supplies and reserves inventory.
9. System creates a delivery entry and adds it to the logistics manifest.
10. System displays a success message for the completed allocation.

## Alternate Flow – Insufficient Stock

4A. System checks inventory and finds insufficient stock for one or more requested items.

4B. System shows an "Insufficient Stock" message and identifies unavailable items.

4C. Disaster Manager can either modify the request quantity or mark the request as pending and arrange external supply.

4D. The use case continues from Step 7 after the required items become available.
