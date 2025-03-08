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
// fields like ID and DateCreated populated.
func (s *Store) Create(ctx context.Context, prd productbus.Product) error {
	const q = `
	INSERT INTO products
		(product_id, user_id, sku, name, description, category, subcategory, upc, brand, manufacturer,
		status, tax_category, unit_of_measure, weight, length, width, height, msrp, cost, minimum_price,
		quantity, is_digital, has_serial_number, has_lot_number, attributes, image_urls, date_created, date_updated)
	VALUES
		(:product_id, :user_id, :sku, :name, :description, :category, :subcategory, :upc, :brand, :manufacturer,
		:status, :tax_category, :unit_of_measure, :weight, :length, :width, :height, :msrp, :cost, :minimum_price,
		:quantity, :is_digital, :has_serial_number, :has_lot_number, :attributes, :image_urls, :date_created, :date_updated)`

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
		name = :name,
		description = :description,
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
		msrp = :msrp,
		cost = :cost,
		minimum_price = :minimum_price,
		quantity = :quantity,
		is_digital = :is_digital,
		has_serial_number = :has_serial_number,
		has_lot_number = :has_lot_number,
		attributes = :attributes,
		image_urls = :image_urls,
		date_updated = :date_updated
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
		product_id, user_id, sku, name, description, category, subcategory, upc, brand, manufacturer,
		status, tax_category, unit_of_measure, weight, length, width, height, msrp, cost, minimum_price,
		quantity, is_digital, has_serial_number, has_lot_number, attributes, image_urls, date_created, date_updated
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

	return toBusProducts(dbPrds)
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
		product_id, user_id, sku, name, description, category, subcategory, upc, brand, manufacturer,
		status, tax_category, unit_of_measure, weight, length, width, height, msrp, cost, minimum_price,
		quantity, is_digital, has_serial_number, has_lot_number, attributes, image_urls, date_created, date_updated
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
		product_id, user_id, sku, name, description, category, subcategory, upc, brand, manufacturer,
		status, tax_category, unit_of_measure, weight, length, width, height, msrp, cost, minimum_price,
		quantity, is_digital, has_serial_number, has_lot_number, attributes, image_urls, date_created, date_updated
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

// CreateVariant adds a Product Variant to the sqldb.
func (s *Store) CreateVariant(ctx context.Context, variant productbus.ProductVariant) error {
	const q = `
	INSERT INTO product_variants
		(variant_id, product_id, sku, variant_options, price, quantity, is_active, date_created, date_updated)
	VALUES
		(:variant_id, :product_id, :sku, :variant_options, :price, :quantity, :is_active, :date_created, :date_updated)`

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
		variant_options = :variant_options,
		price = :price,
		quantity = :quantity,
		is_active = :is_active,
		date_updated = :date_updated
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
		variant_id, product_id, sku, variant_options, price, quantity, is_active, date_created, date_updated
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

// QueryVariantByID gets a specific product variant by ID.
func (s *Store) QueryVariantByID(ctx context.Context, variantID uuid.UUID) (productbus.ProductVariant, error) {
	data := struct {
		ID string `db:"variant_id"`
	}{
		ID: variantID.String(),
	}

	const q = `
	SELECT
		variant_id, product_id, sku, variant_options, price, quantity, is_active, date_created, date_updated
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
