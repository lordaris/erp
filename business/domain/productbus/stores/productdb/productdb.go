package productdb

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lordaris/erp/business/domain/productbus"
	"github.com/lordaris/erp/business/sdk/order"
	"github.com/lordaris/erp/business/sdk/page"
	"github.com/lordaris/erp/business/sdk/sqldb"
	"github.com/lordaris/erp/foundation/logger"
)

// Store manages the set of APIs for product database access.
type Store struct {
	log *logger.Logger
	db  sqlx.ExtContext
}

// NewStore constructs the api for data access.
func NewStore(log *logger.Logger, db *sqlx.DB) *Store {
	return &Store{
		log: log,
		db:  db,
	}
}

// NewWithTx constructs a new Store value replacing the sqlx DB
// value with a sqlx DB value that is currently inside a transaction.
func (s *Store) NewWithTx(tx sqldb.CommitRollbacker) (productbus.Storer, error) {
	ec, err := sqldb.GetExtContext(tx)
	if err != nil {
		return nil, err
	}

	store := Store{
		log: s.log,
		db:  ec,
	}

	return &store, nil
}

// Create adds a Product to the sqldb. It returns the created Product with
// fields like ID and CreatedAt populated.
func (s *Store) Create(ctx context.Context, prd productbus.Product) error {
	const q = `
	INSERT INTO products
		(product_id, user_id, sku, barcode, name, description, short_description, category, subcategory, upc, brand, manufacturer,
		status, tax_category, unit_of_measure, weight, length, width, height, cost_price, wholesale_price, retail_price,
		is_weighted, is_digital, is_taxable, return_policy, has_serial_number, has_lot_number, attributes, image_urls, notes, related_products, created_at, updated_at)
	VALUES
		(:product_id, :user_id, :sku, :barcode, :name, :description, :short_description, :category, :subcategory, :upc, :brand, :manufacturer,
		:status, :tax_category, :unit_of_measure, :weight, :length, :width, :height, :cost_price, :wholesale_price, :retail_price,
		:is_weighted, :is_digital, :is_taxable, :return_policy, :has_serial_number, :has_lot_number, :attributes, :image_urls, :notes, :related_products, :created_at, :updated_at)`

	if err := sqldb.NamedExecContext(ctx, s.log, s.db, q, toDBProduct(prd)); err != nil {
		return fmt.Errorf("namedexeccontext: %w", err)
	}

	return nil
}

// Update modifies data about a product. It will error if the specified ID is
// invalid or does not reference an existing product.
func (s *Store) Update(ctx context.Context, prd productbus.Product) error {
	const q = `
	UPDATE
		products
	SET
		sku = :sku,
		barcode = :barcode,
		name = :name,
		description = :description,
		short_description = :short_description,
		category = :category,
		subcategory = :subcategory,
		upc = :upc,
		brand = :brand,
		manufacturer = :manufacturer,
		status = :status,
		tax_category = :tax_category,
		unit_of_measure = :unit_of_measure,
		weight = :weight,
		length = :length,
		width = :width,
		height = :height,
		cost_price = :cost_price,
		wholesale_price = :wholesale_price,
		retail_price = :retail_price,
		is_weighted = :is_weighted,
		is_digital = :is_digital,
		is_taxable = :is_taxable,
		return_policy = :return_policy,
		has_serial_number = :has_serial_number,
		has_lot_number = :has_lot_number,
		attributes = :attributes,
		image_urls = :image_urls,
		notes = :notes,
		related_products = :related_products,
		updated_at = :updated_at
	WHERE
		product_id = :product_id`

	if err := sqldb.NamedExecContext(ctx, s.log, s.db, q, toDBProduct(prd)); err != nil {
		return fmt.Errorf("namedexeccontext: %w", err)
	}

	return nil
}

// Delete removes the product identified by a given ID.
func (s *Store) Delete(ctx context.Context, prd productbus.Product) error {
	data := struct {
		ID string `db:"product_id"`
	}{
		ID: prd.ID.String(),
	}

	// First delete variants
	const deleteVariants = `
	DELETE FROM
		product_variants
	WHERE
		product_id = :product_id`

	if err := sqldb.NamedExecContext(ctx, s.log, s.db, deleteVariants, data); err != nil {
		return fmt.Errorf("deleting variants: %w", err)
	}

	// Then delete the product
	const deleteProduct = `
	DELETE FROM
		products
	WHERE
		product_id = :product_id`

	if err := sqldb.NamedExecContext(ctx, s.log, s.db, deleteProduct, data); err != nil {
		return fmt.Errorf("deleting product: %w", err)
	}

	return nil
}

// Query gets all Products from the database.
func (s *Store) Query(ctx context.Context, filter productbus.QueryFilter, orderBy order.By, page page.Page) ([]productbus.Product, error) {
	data := map[string]any{
		"offset":        (page.Number() - 1) * page.RowsPerPage(),
		"rows_per_page": page.RowsPerPage(),
	}

	const q = `
	SELECT
		product_id, user_id, sku, barcode, name, description, short_description, category, subcategory, upc, brand, manufacturer,
		status, tax_category, unit_of_measure, weight, length, width, height, cost_price, wholesale_price, retail_price,
		is_weighted, is_digital, is_taxable, return_policy, has_serial_number, has_lot_number, attributes, image_urls, notes, related_products, created_at, updated_at
	FROM
		products`

	buf := bytes.NewBufferString(q)
	s.applyFilter(filter, data, buf)

	orderByClause, err := orderByClause(orderBy)
	if err != nil {
		return nil, err
	}

	buf.WriteString(orderByClause)
	buf.WriteString(" OFFSET :offset ROWS FETCH NEXT :rows_per_page ROWS ONLY")

	var dbPrds []product
	if err := sqldb.NamedQuerySlice(ctx, s.log, s.db, buf.String(), data, &dbPrds); err != nil {
		return nil, fmt.Errorf("namedqueryslice: %w", err)
	}

	prds := make([]productbus.Product, 0, len(dbPrds))
	for _, dbPrd := range dbPrds {
		prd, err := toBusProduct(dbPrd)
		if err != nil {
			return nil, fmt.Errorf("toBusProduct: %w", err)
		}
		prds = append(prds, prd)
	}

	return prds, nil
}

// Count returns the total number of products in the DB.
func (s *Store) Count(ctx context.Context, filter productbus.QueryFilter) (int, error) {
	data := map[string]any{}

	const q = `
	SELECT
		count(1)
	FROM
		products`

	buf := bytes.NewBufferString(q)
	s.applyFilter(filter, data, buf)

	var count struct {
		Count int `db:"count"`
	}
	if err := sqldb.NamedQueryStruct(ctx, s.log, s.db, buf.String(), data, &count); err != nil {
		return 0, fmt.Errorf("db: %w", err)
	}

	return count.Count, nil
}

// QueryByID finds the product identified by a given ID.
func (s *Store) QueryByID(ctx context.Context, productID uuid.UUID) (productbus.Product, error) {
	data := struct {
		ID string `db:"product_id"`
	}{
		ID: productID.String(),
	}

	const q = `
	SELECT
		product_id, user_id, sku, barcode, name, description, short_description, category, subcategory, upc, brand, manufacturer,
		status, tax_category, unit_of_measure, weight, length, width, height, cost_price, wholesale_price, retail_price,
		is_weighted, is_digital, is_taxable, return_policy, has_serial_number, has_lot_number, attributes, image_urls, notes, related_products, created_at, updated_at
	FROM
		products
	WHERE
		product_id = :product_id`

	var dbPrd product
	if err := sqldb.NamedQueryStruct(ctx, s.log, s.db, q, data, &dbPrd); err != nil {
		if errors.Is(err, sqldb.ErrDBNotFound) {
			return productbus.Product{}, fmt.Errorf("db: %w", productbus.ErrNotFound)
		}
		return productbus.Product{}, fmt.Errorf("db: %w", err)
	}

	return toBusProduct(dbPrd)
}

// QueryByUserID finds the product identified by a given User ID.
func (s *Store) QueryByUserID(ctx context.Context, userID uuid.UUID) ([]productbus.Product, error) {
	data := struct {
		ID string `db:"user_id"`
	}{
		ID: userID.String(),
	}

	const q = `
	SELECT
		product_id, user_id, sku, barcode, name, description, short_description, category, subcategory, upc, brand, manufacturer,
		status, tax_category, unit_of_measure, weight, length, width, height, cost_price, wholesale_price, retail_price,
		is_weighted, is_digital, is_taxable, return_policy, has_serial_number, has_lot_number, attributes, image_urls, notes, related_products, created_at, updated_at
	FROM
		products
	WHERE
		user_id = :user_id`

	var dbPrds []product
	if err := sqldb.NamedQuerySlice(ctx, s.log, s.db, q, data, &dbPrds); err != nil {
		return nil, fmt.Errorf("db: %w", err)
	}

	return toBusProducts(dbPrds)
}

// toBusProducts converts a slice of DB products to business products
func toBusProducts(dbPrds []product) ([]productbus.Product, error) {
	prds := make([]productbus.Product, 0, len(dbPrds))
	for _, dbPrd := range dbPrds {
		prd, err := toBusProduct(dbPrd)
		if err != nil {
			return nil, fmt.Errorf("toBusProduct: %w", err)
		}
		prds = append(prds, prd)
	}
	return prds, nil
}

// CreateVariant adds a Product Variant to the sqldb.
func (s *Store) CreateVariant(ctx context.Context, variant productbus.ProductVariant) error {
	const q = `
	INSERT INTO product_variants
		(variant_id, product_id, sku, barcode, variant_options, weight, cost_price, retail_price, current_price, price, quantity, is_active, image_url, created_at, updated_at)
	VALUES
		(:variant_id, :product_id, :sku, :barcode, :variant_options, :weight, :cost_price, :retail_price, :current_price, :price, :quantity, :is_active, :image_url, :created_at, :updated_at)`

	if err := sqldb.NamedExecContext(ctx, s.log, s.db, q, toDBVariant(variant)); err != nil {
		return fmt.Errorf("namedexeccontext: %w", err)
	}

	return nil
}

// UpdateVariant modifies data about a product variant.
func (s *Store) UpdateVariant(ctx context.Context, variant productbus.ProductVariant) error {
	const q = `
	UPDATE
		product_variants
	SET
		sku = :sku,
		barcode = :barcode,
		variant_options = :variant_options,
		weight = :weight,
		cost_price = :cost_price,
		retail_price = :retail_price,
		current_price = :current_price,
		price = :price,
		quantity = :quantity,
		is_active = :is_active,
		image_url = :image_url,
		updated_at = :updated_at
	WHERE
		variant_id = :variant_id`

	if err := sqldb.NamedExecContext(ctx, s.log, s.db, q, toDBVariant(variant)); err != nil {
		return fmt.Errorf("namedexeccontext: %w", err)
	}

	return nil
}

// DeleteVariant removes the product variant identified by a given ID.
func (s *Store) DeleteVariant(ctx context.Context, variantID uuid.UUID) error {
	data := struct {
		ID string `db:"variant_id"`
	}{
		ID: variantID.String(),
	}

	const q = `
	DELETE FROM
		product_variants
	WHERE
		variant_id = :variant_id`

	if err := sqldb.NamedExecContext(ctx, s.log, s.db, q, data); err != nil {
		return fmt.Errorf("namedexeccontext: %w", err)
	}

	return nil
}

// QueryVariantsByProductID gets all variants for a specific product.
func (s *Store) QueryVariantsByProductID(ctx context.Context, productID uuid.UUID) ([]productbus.ProductVariant, error) {
	data := struct {
		ID string `db:"product_id"`
	}{
		ID: productID.String(),
	}

	const q = `
	SELECT
		variant_id, product_id, sku, barcode, variant_options, weight, cost_price, retail_price, current_price, price, quantity, is_active, image_url, created_at, updated_at
	FROM
		product_variants
	WHERE
		product_id = :product_id`

	var dbVariants []productVariant
	if err := sqldb.NamedQuerySlice(ctx, s.log, s.db, q, data, &dbVariants); err != nil {
		return nil, fmt.Errorf("db: %w", err)
	}

	return toBusVariants(dbVariants)
}

// toBusVariants converts a slice of DB variants to business variants
func toBusVariants(dbVariants []productVariant) ([]productbus.ProductVariant, error) {
	variants := make([]productbus.ProductVariant, 0, len(dbVariants))
	for _, dbVariant := range dbVariants {
		variant, err := toBusVariant(dbVariant)
		if err != nil {
			return nil, fmt.Errorf("toBusVariant: %w", err)
		}
		variants = append(variants, variant)
	}
	return variants, nil
}

// QueryVariantByID gets a specific product variant by ID.
func (s *Store) QueryVariantByID(ctx context.Context, variantID uuid.UUID) (productbus.ProductVariant, error) {
	data := struct {
		ID string `db:"variant_id"`
	}{
		ID: variantID.String(),
	}

	const q = `
	SELECT
		variant_id, product_id, sku, barcode, variant_options, weight, cost_price, retail_price, current_price, price, quantity, is_active, image_url, created_at, updated_at
	FROM
		product_variants
	WHERE
		variant_id = :variant_id`

	var dbVariant productVariant
	if err := sqldb.NamedQueryStruct(ctx, s.log, s.db, q, data, &dbVariant); err != nil {
		if errors.Is(err, sqldb.ErrDBNotFound) {
			return productbus.ProductVariant{}, fmt.Errorf("db: variant not found")
		}
		return productbus.ProductVariant{}, fmt.Errorf("db: %w", err)
	}

	return toBusVariant(dbVariant)
}

// QueryVariantsByProductIDs gets all variants for a list of product IDs.
func (s *Store) QueryVariantsByProductIDs(ctx context.Context, productIDs []uuid.UUID) ([]productbus.ProductVariant, error) {
	if len(productIDs) == 0 {
		return []productbus.ProductVariant{}, nil
	}

	// Convert UUIDs to strings for the query
	productIDStrs := make([]string, len(productIDs))
	for i, id := range productIDs {
		productIDStrs[i] = id.String()
	}

	// Use the IN clause with parameters
	data := struct {
		ProductIDs []string `db:"product_ids"`
	}{
		ProductIDs: productIDStrs,
	}

	const q = `
	SELECT
		variant_id, product_id, sku, barcode, variant_options, weight, cost_price, retail_price, 
		current_price, price, quantity, is_active, image_url, created_at, updated_at
	FROM
		product_variants
	WHERE
		product_id IN (:product_ids)`

	var dbVariants []productVariant
	if err := sqldb.NamedQuerySliceUsingIn(ctx, s.log, s.db, q, data, &dbVariants); err != nil {
		return nil, fmt.Errorf("querying variants for multiple products: %w", err)
	}

	return toBusVariants(dbVariants)
}
