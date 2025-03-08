-- Version: 1.01
-- Description: Create table users
CREATE TABLE users (
	user_id       UUID        NOT NULL,
	name          TEXT        NOT NULL,
	email         TEXT UNIQUE NOT NULL,
	roles         TEXT[]      NOT NULL,
	password_hash TEXT        NOT NULL,
    department    TEXT        NULL,
    enabled       BOOLEAN     NOT NULL,
	date_created  TIMESTAMP   NOT NULL,
	date_updated  TIMESTAMP   NOT NULL,

	PRIMARY KEY (user_id)
);

ALTER TABLE products
ADD COLUMN IF NOT EXISTS sku VARCHAR(100),
ADD COLUMN IF NOT EXISTS description TEXT,
ADD COLUMN IF NOT EXISTS category VARCHAR(100),
ADD COLUMN IF NOT EXISTS subcategory VARCHAR(100),
ADD COLUMN IF NOT EXISTS upc VARCHAR(100),
ADD COLUMN IF NOT EXISTS brand VARCHAR(100),
ADD COLUMN IF NOT EXISTS manufacturer VARCHAR(100),
ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'active',
ADD COLUMN IF NOT EXISTS tax_category VARCHAR(100),
ADD COLUMN IF NOT EXISTS unit_of_measure VARCHAR(50),
ADD COLUMN IF NOT EXISTS weight DECIMAL(10, 2),
ADD COLUMN IF NOT EXISTS length DECIMAL(10, 2),
ADD COLUMN IF NOT EXISTS width DECIMAL(10, 2),
ADD COLUMN IF NOT EXISTS height DECIMAL(10, 2),
ADD COLUMN IF NOT EXISTS msrp DECIMAL(10, 2),
ADD COLUMN IF NOT EXISTS minimum_price DECIMAL(10, 2),
ADD COLUMN IF NOT EXISTS is_digital BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS has_serial_number BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS has_lot_number BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS attributes JSONB DEFAULT '{}'::jsonb,
ADD COLUMN IF NOT EXISTS image_urls TEXT[] DEFAULT '{}';

-- Create product_variants table
CREATE TABLE IF NOT EXISTS product_variants (
    variant_id UUID PRIMARY KEY,
    product_id UUID NOT NULL REFERENCES products(product_id) ON DELETE CASCADE,
    sku VARCHAR(100) NOT NULL,
    variant_options TEXT[] NOT NULL DEFAULT '{}',
    price DECIMAL(10, 2) NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    date_created TIMESTAMP WITH TIME ZONE NOT NULL,
    date_updated TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS product_variants_product_id_idx ON product_variants(product_id);
CREATE INDEX IF NOT EXISTS product_variants_sku_idx ON product_variants(sku);-- Version: 1.04
-- Description: Create table homes
CREATE TABLE homes (
    home_id       UUID       NOT NULL,
    type          TEXT       NOT NULL,
    user_id       UUID       NOT NULL,
    address_1     TEXT       NOT NULL,
    address_2     TEXT       NULL,
    zip_code      TEXT       NOT NULL,
    city          TEXT       NOT NULL,
    state         TEXT       NOT NULL,
    country       TEXT       NOT NULL,
    date_created  TIMESTAMP  NOT NULL,
    date_updated  TIMESTAMP  NOT NULL,

    PRIMARY KEY (home_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Description: Create table inventories
CREATE TABLE inventories (
    inventory_id  UUID       NOT NULL,
    product_id    UUID       NOT NULL,
    location      TEXT       NOT NULL,
    name          TEXT       NOT NULL,
    quantity      INT        NOT NULL,
    date_created  TIMESTAMP  NOT NULL,
    date_updated  TIMESTAMP  NOT NULL,

    PRIMARY KEY (inventory_id),
    FOREIGN KEY (product_id) REFERENCES products(product_id) ON DELETE CASCADE
);
