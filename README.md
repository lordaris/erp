The easiest way to start the project is by running:

> go run api/tooling/admin/main.go migrate

> go run api/tooling/admin/main.go seed

> go run api/services/auth/main.go

> go run api/services/sales/main.go

It's possible to configure the project to use kubernetes, docker and other services. You can see the original project
to see the default configuration (I just changed the database host from database-service to localhost:5432) and steps.

# Inventory Management & Manufacturing ERP System

## Domain Models

### 1. Inventory

```go
package inventorybus

type InventoryItem struct {
    ID               uuid.UUID
    Name             name.Name
    SKU              string
    Category         category.Category
    Type             itemtype.ItemType // RawMaterial, WIP, FinishedGood
    Quantity         quantity.Quantity
    UnitOfMeasure    uom.UnitOfMeasure
    MinimumThreshold quantity.Quantity // For reordering
    Cost             money.Money       // Cost per unit
    Location         uuid.UUID         // Reference to warehouse/location
    DateCreated      time.Time
    DateUpdated      time.Time
}

type InventoryTransaction struct {
    ID             uuid.UUID
    ItemID         uuid.UUID
    TransactionType transactiontype.TransactionType // Intake, Consume, Adjust, Move
    Quantity       quantity.Quantity
    FromLocation   uuid.UUID // Optional for moves
    ToLocation     uuid.UUID // Optional for moves
    Reference      string    // PO number, manufacturing order, etc.
    Notes          string
    PerformedBy    uuid.UUID // User who performed transaction
    DatePerformed  time.Time
}
```

### 2. Warehouse & Location Management

```go
package warehousebus

type Warehouse struct {
    ID          uuid.UUID
    Name        name.Name
    Address     address.Address
    IsActive    bool
    DateCreated time.Time
    DateUpdated time.Time
}

type Location struct {
    ID          uuid.UUID
    WarehouseID uuid.UUID
    Code        string      // Like "A-12-C3" for aisle-rack-bin
    Type        loctype.LocationType // Receiving, Shipping, Storage, Production
    Capacity    float64     // Cubic meters or other capacity unit
    IsActive    bool
    DateCreated time.Time
    DateUpdated time.Time
}
```

### 3. Bill of Materials (BOM)

```go
package bombus

type BillOfMaterials struct {
    ID              uuid.UUID
    ProductID       uuid.UUID
    Version         string
    IsActive        bool
    DateCreated     time.Time
    DateUpdated     time.Time
}

type BOMItem struct {
    ID                  uuid.UUID
    BOMID               uuid.UUID
    ItemID              uuid.UUID
    Quantity            quantity.Quantity
    WastagePercentage   float64  // Expected wastage
    IsSubstitutable     bool
    SubstitutionGroupID uuid.UUID // Optional, for alternative materials
    Notes               string
    DateCreated         time.Time
    DateUpdated         time.Time
}
```

### 4. Manufacturing

```go
package manufacturingbus

type ManufacturingProcess struct {
    ID                uuid.UUID
    Name              name.Name
    Description       string
    TargetProductID   uuid.UUID
    BOMID             uuid.UUID // Bill of materials for this process
    EstimatedDuration time.Duration
    IsActive          bool
    DateCreated       time.Time
    DateUpdated       time.Time
}

type ProcessStep struct {
    ID                  uuid.UUID
    ProcessID           uuid.UUID
    StepNumber          int
    Name                name.Name
    Description         string
    WorkCenterID        uuid.UUID
    EstimatedDuration   time.Duration
    LaborRequirement    float64 // Person-hours
    Instructions        string
    DateCreated         time.Time
    DateUpdated         time.Time
}

type WorkCenter struct {
    ID              uuid.UUID
    Name            name.Name
    Description     string
    LocationID      uuid.UUID
    Capacity        int     // How many orders can run concurrently
    HourlyCost      money.Money
    IsActive        bool
    DateCreated     time.Time
    DateUpdated     time.Time
}
```

### 5. Production Orders

```go
package productionbus

type ProductionOrder struct {
    ID                uuid.UUID
    ReferenceNumber   string
    ProductID         uuid.UUID
    ProcessID         uuid.UUID
    Quantity          quantity.Quantity
    Priority          priority.Priority // Low, Medium, High, Critical
    Status            status.Status // Planned, InProgress, Completed, Cancelled
    StartDate         time.Time
    EndDate           time.Time     // Estimated or actual completion
    CreatedBy         uuid.UUID
    DateCreated       time.Time
    DateUpdated       time.Time
}

type ProductionStatus struct {
    ID                 uuid.UUID
    ProductionOrderID  uuid.UUID
    StepID             uuid.UUID
    Status             status.Status // NotStarted, InProgress, Completed, OnHold
    ActualStartTime    time.Time
    ActualEndTime      time.Time
    ActualQuantity     quantity.Quantity // What was actually produced
    QualityCheck       bool
    Notes              string
    RecordedBy         uuid.UUID
    DateCreated        time.Time
    DateUpdated        time.Time
}
```

### 6. Supplier Management

```go
package supplierbus

type Supplier struct {
    ID             uuid.UUID
    Name           name.Name
    ContactPerson  name.Name
    Email          mail.Address
    Phone          string
    Address        address.Address
    IsActive       bool
    Rating         float64      // Supplier performance rating
    DateCreated    time.Time
    DateUpdated    time.Time
}

type SupplierItem struct {
    ID              uuid.UUID
    SupplierID      uuid.UUID
    ItemID          uuid.UUID
    LeadTimeDays    int
    UnitPrice       money.Money
    MinOrderQuantity quantity.Quantity
    PreferredSupplier bool
    DateCreated     time.Time
    DateUpdated     time.Time
}
```

### 7. Purchase Orders

```go
package purchasebus

type PurchaseOrder struct {
    ID                uuid.UUID
    PoNumber          string
    SupplierID        uuid.UUID
    Status            status.Status // Draft, Sent, Received, Cancelled
    ExpectedDelivery  time.Time
    ShippingTerms     string
    PaymentTerms      string
    TotalAmount       money.Money
    Notes             string
    CreatedBy         uuid.UUID
    DateCreated       time.Time
    DateUpdated       time.Time
}

type POItem struct {
    ID               uuid.UUID
    PurchaseOrderID  uuid.UUID
    ItemID           uuid.UUID
    Quantity         quantity.Quantity
    UnitPrice        money.Money
    ExpectedDelivery time.Time
    ReceivedQuantity quantity.Quantity
    LineStatus       status.Status // Ordered, PartiallyReceived, FullyReceived, Cancelled
    DateCreated      time.Time
    DateUpdated      time.Time
}
```

### 8. Quality Control

```go
package qualitybus

type InspectionType struct {
    ID             uuid.UUID
    Name           name.Name
    Description    string
    IsActive       bool
    DateCreated    time.Time
    DateUpdated    time.Time
}

type QCCheckpoint struct {
    ID                uuid.UUID
    InspectionTypeID  uuid.UUID
    ProcessStepID     uuid.UUID  // Optional, link to manufacturing step
    Name              name.Name
    Description       string
    IsActive          bool
    DateCreated       time.Time
    DateUpdated       time.Time
}

type QCInspection struct {
    ID                 uuid.UUID
    CheckpointID       uuid.UUID
    ReferenceID        uuid.UUID  // Could be ProductionOrder, PurchaseOrder, etc
    ReferenceType      string     // Type of the reference (production, purchase, etc)
    Result             bool       // Pass/Fail
    Notes              string
    InspectedBy        uuid.UUID
    DateInspected      time.Time
    DateCreated        time.Time
    DateUpdated        time.Time
}
```

## System Architecture

The ERP system will follow the same architectural patterns as the existing code:

1. **Domain Business Logic**: Contains all business rules and domain-specific logic
2. **Data Stores**: Database access layer for each domain
3. **API Layer**: RESTful endpoints for client interaction
4. **Middleware**: Authentication, error handling, logging

### Interactions Between Domains

- **Production Planning**:

  - When a production order is created, it checks inventory levels for required materials
  - If insufficient materials, triggers purchase requisitions
  - Schedules work centers based on capacity and order priority

- **Inventory Management**:

  - When materials are received, inventory is updated
  - When production consumes materials, inventory is reduced
  - Low stock triggers alerts and potential purchase orders

- **Quality Control**:
  - QC checkpoints integrated into production steps
  - Failed inspections can hold production or reject materials
  - QC metrics feed into supplier ratings

## API Endpoints

Following the established pattern, each domain will have standard CRUD endpoints plus specialized operations:

```
GET /v1/inventory                    // List inventory with filters
GET /v1/inventory/{item_id}          // Get specific inventory item
POST /v1/inventory                   // Create new inventory item
PUT /v1/inventory/{item_id}          // Update inventory item
DELETE /v1/inventory/{item_id}       // Delete inventory item

POST /v1/inventory/transactions      // Record inventory movement/adjustment

GET /v1/production/orders            // List production orders
POST /v1/production/orders           // Create production order
PUT /v1/production/orders/{order_id} // Update production order
GET /v1/production/schedule          // Get production schedule

GET /v1/qc/inspections               // List quality inspections
POST /v1/qc/inspections              // Record inspection results
```

## Integration Points

- **User System**: Leverage existing user management for authentication and authorization
- **Product System**: Use product data for BOMs and production targets
- **Reporting**: Create dashboard views for inventory levels, production efficiency

## Advanced Features

- **Demand Forecasting**: ML-based prediction of material needs based on historical data
- **Just-in-Time Inventory**: Optimize inventory levels to minimize carrying costs
- **Barcode/RFID Integration**: Real-time tracking of inventory movements
- **Supplier Performance Analytics**: Track supplier reliability, quality, and pricing

# Point of Sale (POS) System Design

## Domain Models

### 1. Stores & Registers

```go
package storebus

type Store struct {
    ID           uuid.UUID
    Name         name.Name
    Code         string
    Address      address.Address
    PhoneNumber  string
    ManagerID    uuid.UUID  // User reference
    IsActive     bool
    DateCreated  time.Time
    DateUpdated  time.Time
}

type Register struct {
    ID          uuid.UUID
    StoreID     uuid.UUID
    Code        string      // Unique identifier in the store
    Name        string      // e.g., "Front Counter 1"
    IsActive    bool
    LastOpenedBy uuid.UUID  // Last user who opened the register
    DateCreated time.Time
    DateUpdated time.Time
}

type RegisterSession struct {
    ID             uuid.UUID
    RegisterID     uuid.UUID
    UserID         uuid.UUID
    OpenedTime     time.Time
    ClosedTime     time.Time
    StartingAmount money.Money
    EndingAmount   money.Money
    Status         sessionstatus.SessionStatus // Open, Closed, ForceClose
    Notes          string
    DateCreated    time.Time
    DateUpdated    time.Time
}
```

### 2. Customers

```go
package customerbus

type Customer struct {
    ID              uuid.UUID
    FirstName       string
    LastName        string
    CompanyName     string
    Email           mail.Address
    Phone           string
    BillingAddress  address.Address
    ShippingAddress address.Address
    TaxExempt       bool
    TaxID           string
    CustomerGroup   customergroup.CustomerGroup
    DateCreated     time.Time
    DateUpdated     time.Time
}

type CustomerGroup struct {
    ID          uuid.UUID
    Name        string
    Description string
    DiscountPercentage float64
    IsActive    bool
    DateCreated time.Time
    DateUpdated time.Time
}
```

### 3. Sales Transactions

```go
package salesbus

type Sale struct {
    ID               uuid.UUID
    SaleNumber       string
    StoreID          uuid.UUID
    RegisterID       uuid.UUID
    CustomerID       uuid.UUID      // Optional, for anonymous sales
    UserID           uuid.UUID      // Cashier
    SaleDate         time.Time
    Status           salestatus.SaleStatus // InProgress, Completed, Voided, Returned
    SubTotal         money.Money
    TaxAmount        money.Money
    DiscountAmount   money.Money
    TotalAmount      money.Money
    Notes            string
    DateCreated      time.Time
    DateUpdated      time.Time
}

type SaleItem struct {
    ID              uuid.UUID
    SaleID          uuid.UUID
    ProductID       uuid.UUID
    Quantity        quantity.Quantity
    UnitPrice       money.Money
    DiscountPercent float64
    DiscountAmount  money.Money
    TaxPercent      float64
    TaxAmount       money.Money
    LineTotal       money.Money
    Notes           string
    DateCreated     time.Time
    DateUpdated     time.Time
}

type SalePayment struct {
    ID               uuid.UUID
    SaleID           uuid.UUID
    PaymentMethod    paymentmethod.PaymentMethod // Cash, CreditCard, DebitCard, GiftCard
    Amount           money.Money
    CardNumber       string      // Last 4 digits for card payments
    AuthorizationID  string      // For card payments
    Status           paymentstatus.PaymentStatus // Approved, Declined, Voided
    Notes            string
    DateCreated      time.Time
    DateUpdated      time.Time
}
```

### 4. Returns & Exchanges

```go
package returnsbus

type Return struct {
    ID               uuid.UUID
    ReturnNumber     string
    OriginalSaleID   uuid.UUID
    StoreID          uuid.UUID
    RegisterID       uuid.UUID
    CustomerID       uuid.UUID
    UserID           uuid.UUID      // Employee processing return
    ReturnDate       time.Time
    Status           returnstatus.ReturnStatus // InProgress, Completed, Voided
    ReturnReason     string
    TotalAmount      money.Money
    Notes            string
    DateCreated      time.Time
    DateUpdated      time.Time
}

type ReturnItem struct {
    ID              uuid.UUID
    ReturnID        uuid.UUID
    SaleItemID      uuid.UUID     // Link to original sale item
    ProductID       uuid.UUID
    Quantity        quantity.Quantity
    UnitPrice       money.Money
    LineTotal       money.Money
    ReturnType      returntype.ReturnType // Refund, Exchange, StoreCredit
    ExchangeItemID  uuid.UUID    // For exchanges, the new item
    Notes           string
    DateCreated     time.Time
    DateUpdated     time.Time
}

type ReturnPayment struct {
    ID               uuid.UUID
    ReturnID         uuid.UUID
    PaymentMethod    paymentmethod.PaymentMethod
    Amount           money.Money
    OriginalPaymentID uuid.UUID   // Link to original payment
    Status           paymentstatus.PaymentStatus
    Notes            string
    DateCreated      time.Time
    DateUpdated      time.Time
}
```

### 5. Discounts & Promotions

```go
package promotionbus

type Promotion struct {
    ID                 uuid.UUID
    Name               string
    Description        string
    PromotionType      promotiontype.PromotionType // PercentOff, AmountOff, BuyXGetY, etc
    DiscountValue      float64     // Percentage or fixed amount
    MinimumPurchase    money.Money // Minimum purchase amount if applicable
    StartDate          time.Time
    EndDate            time.Time
    IsActive           bool
    AppliesTo          promotiontarget.PromotionTarget // AllItems, SpecificItems, Categories
    LimitPerCustomer   int         // 0 means unlimited
    DateCreated        time.Time
    DateUpdated        time.Time
}

type PromotionItem struct {
    ID                uuid.UUID
    PromotionID       uuid.UUID
    ItemID            uuid.UUID    // Product ID
    CategoryID        uuid.UUID    // Category ID (mutually exclusive with ItemID)
    RequiredQuantity  int          // For BuyXGetY promotions
    FreeQuantity      int          // For BuyXGetY promotions
    DateCreated       time.Time
    DateUpdated       time.Time
}

type Coupon struct {
    ID                uuid.UUID
    Code              string
    PromotionID       uuid.UUID
    IsActive          bool
    UsageLimit        int         // How many times can the coupon be used
    UsageCount        int         // How many times it has been used
    DateCreated       time.Time
    DateUpdated       time.Time
}
```

### 6. Gift Cards & Store Credit

```go
package giftcardbus

type GiftCard struct {
    ID                uuid.UUID
    Code              string
    InitialBalance    money.Money
    CurrentBalance    money.Money
    IsActive          bool
    ActivationDate    time.Time
    ExpiryDate        time.Time    // Optional
    PurchaseID        uuid.UUID    // Sale where it was purchased (optional)
    DateCreated       time.Time
    DateUpdated       time.Time
}

type GiftCardTransaction struct {
    ID                uuid.UUID
    GiftCardID        uuid.UUID
    TransactionType   transtype.TransactionType // Activate, Redeem, Reload, Void
    Amount            money.Money
    ReferenceID       uuid.UUID    // Sale or Return ID
    ReferenceType     string       // "Sale" or "Return"
    Notes             string
    DateCreated       time.Time
}

type StoreCredit struct {
    ID                uuid.UUID
    CustomerID        uuid.UUID
    InitialAmount     money.Money
    CurrentAmount     money.Money
    IsActive          bool
    ExpiryDate        time.Time    // Optional
    IssueReason       string       // Return, Compensation, etc
    DateCreated       time.Time
    DateUpdated       time.Time
}

type StoreCreditTransaction struct {
    ID                uuid.UUID
    StoreCreditID     uuid.UUID
    TransactionType   transtype.TransactionType // Issue, Redeem, Void
    Amount            money.Money
    ReferenceID       uuid.UUID    // Sale or Return ID
    ReferenceType     string       // "Sale" or "Return"
    Notes             string
    DateCreated       time.Time
}
```

### 7. Pricing & Tax Configuration

```go
package pricingbus

type PriceList struct {
    ID                uuid.UUID
    Name              string
    Description       string
    IsDefault         bool
    StartDate         time.Time
    EndDate           time.Time    // Optional
    IsActive          bool
    DateCreated       time.Time
    DateUpdated       time.Time
}

type PriceItem struct {
    ID                uuid.UUID
    PriceListID       uuid.UUID
    ProductID         uuid.UUID
    Price             money.Money
    DateCreated       time.Time
    DateUpdated       time.Time
}

type TaxRate struct {
    ID                uuid.UUID
    Name              string
    Rate              float64      // As decimal (0.07 = 7%)
    AppliesTo         taxapplication.TaxApplication // AllProducts, Categories, SpecificProducts
    CountryCode       string
    StateCode         string
    ZipCode           string       // Optional, for more granular taxation
    IsActive          bool
    DateCreated       time.Time
    DateUpdated       time.Time
}

type TaxRateItem struct {
    ID                uuid.UUID
    TaxRateID         uuid.UUID
    ItemID            uuid.UUID    // Product ID (optional)
    CategoryID        uuid.UUID    // Category ID (optional)
    IsExempt          bool         // If true, this explicitly exempts the item
    DateCreated       time.Time
    DateUpdated       time.Time
}
```

## API Endpoints

```go
# Stores & Registers
GET    /v1/stores                           // List stores with filters
GET    /v1/stores/{store_id}                // Get specific store
POST   /v1/stores                           // Create new store
PUT    /v1/stores/{store_id}                // Update store
DELETE /v1/stores/{store_id}                // Delete store

GET    /v1/registers                        // List registers with filters
POST   /v1/registers/{register_id}/open     // Open register session
POST   /v1/registers/{register_id}/close    // Close register session
GET    /v1/registers/{register_id}/session  // Get current session details

# Customers
GET    /v1/customers                        // List customers with filters
GET    /v1/customers/{customer_id}          // Get specific customer
POST   /v1/customers                        // Create new customer
PUT    /v1/customers/{customer_id}          // Update customer
GET    /v1/customers/{customer_id}/sales    // Get customer purchase history

# Sales
POST   /v1/sales                            // Create new sale
PUT    /v1/sales/{sale_id}                  // Update sale
GET    /v1/sales/{sale_id}                  // Get sale details
POST   /v1/sales/{sale_id}/complete         // Complete transaction
POST   /v1/sales/{sale_id}/void             // Void transaction
GET    /v1/sales                            // List sales with filters
POST   /v1/sales/{sale_id}/items            // Add items to sale
DELETE /v1/sales/{sale_id}/items/{item_id}  // Remove item from sale
POST   /v1/sales/{sale_id}/payments         // Add payment to sale

# Returns & Exchanges
POST   /v1/returns                          // Create return/exchange
PUT    /v1/returns/{return_id}              // Update return
GET    /v1/returns/{return_id}              // Get return details
POST   /v1/returns/{return_id}/complete     // Complete return processing
GET    /v1/returns                          // List returns with filters

# Promotions
GET    /v1/promotions                       // List active promotions
POST   /v1/promotions                       // Create new promotion
PUT    /v1/promotions/{promotion_id}        // Update promotion
GET    /v1/sales/{sale_id}/applycoupon      // Apply coupon to sale

# Gift Cards
POST   /v1/giftcards                        // Create new gift card
GET    /v1/giftcards/{code}/balance         // Check gift card balance
POST   /v1/giftcards/{code}/reload          // Add value to gift card
GET    /v1/storecredits/{customer_id}       // Get customer's store credit
```

## Integration with Inventory

The POS system integrates closely with the Inventory Management module:

1. **Real-time Inventory Updates**:

   - When a sale is completed, inventory levels are automatically reduced
   - Returns increase inventory levels
   - Low stock alerts can be triggered during sales

2. **Inventory Visibility**:

   - POS shows real-time availability across all locations
   - Can show estimated arrival dates for out-of-stock items

3. **Item Lookups**:
   - Barcode scanning integration
   - Item search by name, SKU, or description
   - Display of item details, pricing, and promotions

## Reports and Analytics

The POS system offers rich reporting capabilities:

1. **Sales Analytics**:

   - Sales by time period (hourly, daily, weekly, monthly)
   - Sales by product, category, or department
   - Sales by employee
   - Sales by payment method

2. **Customer Insights**:

   - Purchase history and patterns
   - Customer lifetime value
   - Frequency of visits
   - Popular products by customer group

3. **Inventory Reports**:

   - Best and worst selling items
   - Inventory turnover rates
   - Product margin analysis
   - Shrinkage tracking (theft, damage, etc.)

4. **Financial Reports**:
   - Register reconciliation
   - Tax collection reports
   - Discount and promotion effectiveness
   - Return rates and reasons

## Advanced Features

1. **Omnichannel Integration**:

   - Unified inventory across in-store and online sales
   - Buy online, pickup in-store (BOPIS) support
   - Ship from store capability
   - Cross-channel returns processing

2. **Customer Engagement**:

   - Loyalty program integration
   - Customer-facing displays with promotional content
   - Digital receipts and automated follow-ups
   - Personalized offers based on purchase history

3. **Employee Management**:

   - Role-based permissions
   - Time tracking integration
   - Performance metrics (sales per hour, average transaction value)
   - Commission calculation

4. **Payment Processing**:

   - EMV chip card support
   - Contactless payments (NFC)
   - Mobile wallet integration (Apple Pay, Google Pay)
   - Split payment methods
   - Layaway and partial payment plans

5. **Security Features**:
   - End-to-end encryption
   - Fraud detection algorithms
   - PCI-DSS compliance
   - Void and return a# Financial & Accounting Module

## Domain Models

### 1. Chart of Accounts

```go
package accountingbus

type AccountClass struct {
    ID          uuid.UUID
    Code        string
    Name        string
    Description string
    Type        accounttype.AccountType // Asset, Liability, Equity, Revenue, Expense
    DateCreated time.Time
    DateUpdated time.Time
}

type AccountGroup struct {
    ID          uuid.UUID
    ClassID     uuid.UUID
    Code        string
    Name        string
    Description string
    DateCreated time.Time
    DateUpdated time.Time
}

type Account struct {
    ID          uuid.UUID
    GroupID     uuid.UUID
    Code        string
    Name        string
    Description string
    IsActive    bool
    Balance     money.Money
    DateCreated time.Time
    DateUpdated time.Time
}
```

### 2. General Ledger

```go
package ledgerbus

type JournalEntry struct {
    ID             uuid.UUID
    EntryNumber    string
    EntryDate      time.Time
    Description    string
    Reference      string        // Invoice number, payment number, etc.
    ReferenceType  string        // Invoice, Payment, Adjustment, etc.
    Status         entrystatus.EntryStatus // Draft, Posted, Voided
    TotalDebit     money.Money
    TotalCredit    money.Money
    CreatedBy      uuid.UUID
    PostedBy       uuid.UUID
    DateCreated    time.Time
    DateUpdated    time.Time
}

type JournalLine struct {
    ID             uuid.UUID
    JournalEntryID uuid.UUID
    AccountID      uuid.UUID
    Description    string
    DebitAmount    money.Money
    CreditAmount   money.Money
    DateCreated    time.Time
    DateUpdated    time.Time
}

type FiscalYear struct {
    ID             uuid.UUID
    Name           string
    StartDate      time.Time
    EndDate        time.Time
    IsClosed       bool
    DateCreated    time.Time
    DateUpdated    time.Time
}

type FiscalPeriod struct {
    ID             uuid.UUID
    FiscalYearID   uuid.UUID
    Name           string
    StartDate      time.Time
    EndDate        time.Time
    IsClosed       bool
    DateCreated    time.Time
    DateUpdated    time.Time
}
```

### 3. Accounts Receivable

```go
package arbus

type Invoice struct {
    ID               uuid.UUID
    InvoiceNumber    string
    CustomerID       uuid.UUID
    InvoiceDate      time.Time
    DueDate          time.Time
    Status           invoicestatus.InvoiceStatus // Draft, Sent, Partially Paid, Paid, Voided
    ReferenceType    string        // Order, Contract, etc.
    ReferenceID      uuid.UUID     // ID of the reference
    SubTotal         money.Money
    TaxAmount        money.Money
    DiscountAmount   money.Money
    TotalAmount      money.Money
    AmountPaid       money.Money
    Notes            string
    CreatedBy        uuid.UUID
    DateCreated      time.Time
    DateUpdated      time.Time
}

type InvoiceLine struct {
    ID               uuid.UUID
    InvoiceID        uuid.UUID
    ProductID        uuid.UUID     // Optional, for product-based lines
    Description      string
    Quantity         quantity.Quantity
    UnitPrice        money.Money
    TaxPercent       float64
    TaxAmount        money.Money
    DiscountPercent  float64
    DiscountAmount   money.Money
    LineTotal        money.Money
    DateCreated      time.Time
    DateUpdated      time.Time
}

type CustomerPayment struct {
    ID               uuid.UUID
    PaymentNumber    string
    CustomerID       uuid.UUID
    PaymentDate      time.Time
    PaymentMethod    paymentmethod.PaymentMethod
    Amount           money.Money
    Reference        string      // Check number, transaction ID, etc.
    Notes            string
    CreatedBy        uuid.UUID
    DateCreated      time.Time
    DateUpdated      time.Time
}

type PaymentAllocation struct {
    ID               uuid.UUID
    PaymentID        uuid.UUID
    InvoiceID        uuid.UUID
    Amount           money.Money
    DateCreated      time.Time
    DateUpdated      time.Time
}
```

### 4. Accounts Payable

```go
package apbus

type VendorInvoice struct {
    ID               uuid.UUID
    InvoiceNumber    string
    SupplierID       uuid.UUID
    InvoiceDate      time.Time
    DueDate          time.Time
    Status           invoicestatus.InvoiceStatus // Draft, Received, Partially Paid, Paid, Voided
    ReferenceType    string        // PO, Contract, etc.
    ReferenceID      uuid.UUID     // ID of the reference
    SubTotal         money.Money
    TaxAmount        money.Money
    TotalAmount      money.Money
    AmountPaid       money.Money
    Notes            string
    CreatedBy        uuid.UUID
    DateCreated      time.Time
    DateUpdated      time.Time
}

type VendorInvoiceLine struct {
    ID               uuid.UUID
    InvoiceID        uuid.UUID
    ProductID        uuid.UUID     // Optional, for product-based lines
    Description      string
    Quantity         quantity.Quantity
    UnitPrice        money.Money
    TaxPercent       float64
    TaxAmount        money.Money
    LineTotal        money.Money
    DateCreated      time.Time
    DateUpdated      time.Time
}

type VendorPayment struct {
    ID               uuid.UUID
    PaymentNumber    string
    SupplierID       uuid.UUID
    PaymentDate      time.Time
    PaymentMethod    paymentmethod.PaymentMethod
    Amount           money.Money
    Reference        string      // Check number, transaction ID, etc.
    Notes            string
    CreatedBy        uuid.UUID
    DateCreated      time.Time
    DateUpdated      time.Time
}

type VendorPaymentAllocation struct {
    ID               uuid.UUID
    PaymentID        uuid.UUID
    InvoiceID        uuid.UUID
    Amount           money.Money
    DateCreated      time.Time
    DateUpdated      time.Time
}
```

### 5. Asset Management

```go
package assetbus

type Asset struct {
    ID                uuid.UUID
    Name              string
    AssetNumber       string
    Description       string
    AssetType         assettype.AssetType  // Fixed, Intangible, etc.
    PurchaseDate      time.Time
    InitialCost       money.Money
    CurrentValue      money.Money
    ResidualValue     money.Money
    LifeExpectancy    int           // In months
    DepreciationMethod depmethod.DepreciationMethod // Straight Line, Declining Balance, etc.
    AssetAccount      uuid.UUID     // Account ID for the asset
    DepreciationAccount uuid.UUID   // Account ID for accumulated depreciation
    ExpenseAccount    uuid.UUID     // Account ID for depreciation expense
    Notes             string
    DateCreated       time.Time
    DateUpdated       time.Time
}

type AssetDepreciation struct {
    ID                uuid.UUID
    AssetID           uuid.UUID
    PeriodStart       time.Time
    PeriodEnd         time.Time
    DepreciationAmount money.Money
    BookValue         money.Money
    JournalEntryID    uuid.UUID     // Reference to GL entry
    DateCreated       time.Time
    DateUpdated       time.Time
}
```

### 6. Budgeting & Forecasting

```go
package budgetbus

type Budget struct {
    ID                uuid.UUID
    Name              string
    Description       string
    StartDate         time.Time
    EndDate           time.Time
    Status            budgetstatus.BudgetStatus // Draft, Approved, Closed
    CreatedBy         uuid.UUID
    ApprovedBy        uuid.UUID
    DateCreated       time.Time
    DateUpdated       time.Time
}

type BudgetLine struct {
    ID                uuid.UUID
    BudgetID          uuid.UUID
    AccountID         uuid.UUID
    Description       string
    AnnualAmount      money.Money
    JanAmount         money.Money
    FebAmount         money.Money
    MarAmount         money.Money
    AprAmount         money.Money
    MayAmount         money.Money
    JunAmount         money.Money
    JulAmount         money.Money
    AugAmount         money.Money
    SepAmount         money.Money
    OctAmount         money.Money
    NovAmount         money.Money
    DecAmount         money.Money
    DateCreated       time.Time
    DateUpdated       time.Time
}

type Forecast struct {
    ID                uuid.UUID
    Name              string
    Description       string
    StartDate         time.Time
    EndDate           time.Time
    BasedOn           forecastbase.ForecastBase // Historical, Budget, Manual
    CreatedBy         uuid.UUID
    DateCreated       time.Time
    DateUpdated       time.Time
}

type ForecastLine struct {
    ID                uuid.UUID
    ForecastID        uuid.UUID
    AccountID         uuid.UUID
    Description       string
    AnnualAmount      money.Money
    MonthlyAmounts    []money.Money // 12 months
    DateCreated       time.Time
    DateUpdated       time.Time
}
```

### 7. Financial Reporting

```go
package financialreportbus

type FinancialStatement struct {
    ID                uuid.UUID
    StatementType     statementtype.StatementType // IncomeStatement, BalanceSheet, CashFlow
    Name              string
    Description       string
    StartDate         time.Time
    EndDate           time.Time
    ComparisonType    comparisontype.ComparisonType // None, PreviousPeriod, PreviousYear, Budget
    CreatedBy         uuid.UUID
    DateCreated       time.Time
    DateUpdated       time.Time
}

type StatementSection struct {
    ID                uuid.UUID
    StatementID       uuid.UUID
    ParentSectionID   uuid.UUID     // For nested sections
    Name              string
    Description       string
    SortOrder         int
    ShowTotal         bool
    DateCreated       time.Time
    DateUpdated       time.Time
}

type StatementLine struct {
    ID                uuid.UUID
    SectionID         uuid.UUID
    AccountID         uuid.UUID     // Optional, can be calculated or linked to account
    Description       string
    Formula           string        // For calculated lines
    SortOrder         int
    IsTotal           bool
    DateCreated       time.Time
    DateUpdated       time.Time
}
```

## API Endpoints

```
# Chart of Accounts
GET    /v1/accounts                       // List accounts with filters
GET    /v1/accounts/{account_id}          // Get specific account
POST   /v1/accounts                       // Create new account
PUT    /v1/accounts/{account_id}          // Update account
GET    /v1/accounts/{account_id}/balance  // Get account balance

# General Ledger
POST   /v1/journal/entries                // Create new journal entry
GET    /v1/journal/entries                // List journal entries with filters
GET    /v1/journal/entries/{entry_id}     // Get specific journal entry
POST   /v1/journal/entries/{entry_id}/post // Post a journal entry
POST   /v1/journal/entries/{entry_id}/void // Void a journal entry

# Accounts Receivable
POST   /v1/invoices                       // Create new customer invoice
GET    /v1/invoices                       // List invoices with filters
GET    /v1/invoices/{invoice_id}          // Get specific invoice
PUT    /v1/invoices/{invoice_id}          // Update invoice
POST   /v1/invoices/{invoice_id}/send     // Mark invoice as sent
POST   /v1/payments                       // Record customer payment
GET    /v1/customers/{customer_id}/balance // Get customer balance
GET    /v1/reports/aged-receivables       // Aged receivables report

# Accounts Payable
POST   /v1/vendor/invoices                // Create new vendor invoice
GET    /v1/vendor/invoices                // List vendor invoices with filters
POST   /v1/vendor/payments                // Record vendor payment
GET    /v1/suppliers/{supplier_id}/balance // Get supplier balance
GET    /v1/reports/aged-payables          // Aged payables report

# Asset Management
POST   /v1/assets                         // Create new asset
GET    /v1/assets                         // List assets with filters
POST   /v1/assets/{asset_id}/depreciate   // Run depreciation
GET    /v1/assets/{asset_id}/depreciation-schedule // Get depreciation schedule

# Financial Reporting
GET    /v1/reports/balance-sheet          // Generate balance sheet
GET    /v1/reports/income-statement       // Generate income statement
GET    /v1/reports/cash-flow              // Generate cash flow statement
POST   /v1/reports/custom                 // Generate custom financial report
GET    /v1/reports/budget-variance        // Budget vs actual report
```

## Integration with Other Modules

The Financial & Accounting module integrates with:

1. **Sales & POS**:

   - Automated journal entries for sales transactions
   - Revenue recognition
   - Customer payment tracking

2. **Inventory & Manufacturing**:

   - Cost of goods sold calculations
   - Inventory valuation
   - Manufacturing cost accounting

3. **Purchasing & AP**:
   - Vendor payment processing
   - Purchase order to invoice matching
   - Expense tracking

## Financial Dashboards

1. **Executive Dashboard**:

   - Key financial ratios
   - Cash position
   - Revenue trends
   - Profitability analysis

2. **Cash Management**:

   - Cash flow projections
   - Receivables aging
   - Payables scheduling
   - Bank account reconciliation

3. **Financial Performance**:
   - Budget vs actual comparisons
   - Department expense analysis
   - Cost center performance metrics
   - Profitability by product line/division

## Advanced Features

1. **Multi-Currency Support**:

   - Currency conversion
   - Exchange rate management
   - Foreign currency revaluation
   - Multi-currency reporting

2. **Tax Management**:

   - Sales tax tracking and reporting
   - VAT/GST handling
   - Tax authority integrations
   - Tax audit preparation

3. **Financial Controls**:

   - Automated account reconciliation
   - Audit trails for all transactions
   - Approval workflows for large transactions
   - Segregation of duties enforcement

4. **Compliance & Reporting**:

   - GAAP/IFRS compliance
   - Regulatory reporting
   - Financial statement preparation
   - Audit support tooling

5. **Business Intelligence**:
   - Financial trend analysis
   - Predictive cash flow modeling
   - Profitability forecasting
   - What-if scenario planninguthorization levels

```go
// Package inventorybus provides business access to inventory domain.
package inventorybus

import (
"time"

    "github.com/ardanlabs/service/business/types/money"
    "github.com/ardanlabs/service/business/types/name"
    "github.com/ardanlabs/service/business/types/quantity"
    "github.com/google/uuid"

)

// InventoryItem represents an individual inventory item.
type InventoryItem struct {
ID uuid.UUID
SKU string
Name name.Name
Category category.Category
Type itemtype.ItemType // RawMaterial, WIP, FinishedGood
Quantity quantity.Quantity
UnitOfMeasure uom.UnitOfMeasure
MinimumThreshold quantity.Quantity // For reordering
Cost money.Money // Cost per unit
LocationID uuid.UUID // Reference to warehouse/location
DateCreated time.Time
DateUpdated time.Time
}

// NewInventoryItem is what we require from clients when adding an inventory item.
type NewInventoryItem struct {
SKU string
Name name.Name
Category category.Category
Type itemtype.ItemType
Quantity quantity.Quantity
UnitOfMeasure uom.UnitOfMeasure
MinimumThreshold quantity.Quantity
Cost money.Money
LocationID uuid.UUID
}

// UpdateInventoryItem defines what information may be provided to modify an
// existing inventory item. All fields are optional so clients can send just the
// fields they want changed.
type UpdateInventoryItem struct {
SKU *string
Name*name.Name
Category *category.Category
Type*itemtype.ItemType
Quantity *quantity.Quantity
UnitOfMeasure*uom.UnitOfMeasure
MinimumThreshold *quantity.Quantity
Cost*money.Money
LocationID \*uuid.UUID
}

// InventoryTransaction represents a movement or adjustment to inventory.
type InventoryTransaction struct {
ID uuid.UUID
ItemID uuid.UUID
TransactionType transactiontype.TransactionType // Intake, Consume, Adjust, Move
Quantity quantity.Quantity
FromLocation uuid.UUID // Optional for moves
ToLocation uuid.UUID // Optional for moves
Reference string // PO number, manufacturing order, etc.
Notes string
PerformedBy uuid.UUID // User who performed transaction
DatePerformed time.Time
DateCreated time.Time
DateUpdated time.Time
}

// NewInventoryTransaction defines the data needed to create a new inventory transaction.
type NewInventoryTransaction struct {
ItemID uuid.UUID
TransactionType transactiontype.TransactionType
Quantity quantity.Quantity
FromLocation uuid.UUID
ToLocation uuid.UUID
Reference string
Notes string
PerformedBy uuid.UUID
}

// QueryFilter holds the available fields a query can be filtered on.
type QueryFilter struct {
ID *uuid.UUID
SKU*string
Name *name.Name
Category*category.Category
Type *itemtype.ItemType
LocationID*uuid.UUID
BelowThreshold \*bool // Items with quantity below threshold
}

```
