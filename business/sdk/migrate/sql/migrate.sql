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

CREATE TABLE products (
    product_id         UUID        PRIMARY KEY,
    user_id            UUID        NOT NULL,
    sku                VARCHAR(50),
    name               VARCHAR(100) NOT NULL,
    description        TEXT,
    category           VARCHAR(100),
    subcategory        VARCHAR(100),
    upc                VARCHAR(14),
    brand              VARCHAR(100),
    manufacturer       VARCHAR(100),
    status             VARCHAR(20) DEFAULT 'ACTIVE',
    tax_category       VARCHAR(20) DEFAULT 'STANDARD',
    unit_of_measure    VARCHAR(20) DEFAULT 'EACH',
    weight             DECIMAL(10,2) DEFAULT 0,
    length             DECIMAL(10,2) DEFAULT 0,
    width              DECIMAL(10,2) DEFAULT 0,
    height             DECIMAL(10,2) DEFAULT 0,
    msrp               DECIMAL(10,2) DEFAULT 0,
    cost               DECIMAL(10,2) NOT NULL,
    minimum_price      DECIMAL(10,2) DEFAULT 0,
    quantity           INTEGER NOT NULL,
    is_digital         BOOLEAN DEFAULT FALSE,
    has_serial_number  BOOLEAN DEFAULT FALSE,
    has_lot_number     BOOLEAN DEFAULT FALSE,
    attributes         JSONB DEFAULT '{}',
    image_urls         JSONB DEFAULT '[]',
    date_created       TIMESTAMP NOT NULL,
    date_updated       TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE product_variants (
    variant_id       UUID        PRIMARY KEY,
    product_id       UUID        NOT NULL,
    sku              VARCHAR(50) NOT NULL,
    variant_options  JSONB       NOT NULL,
    price            DECIMAL(10,2) NOT NULL,
    quantity         INTEGER     NOT NULL,
    is_active        BOOLEAN     DEFAULT TRUE,
    date_created     TIMESTAMP   NOT NULL,
    date_updated     TIMESTAMP   NOT NULL,
    FOREIGN KEY (product_id) REFERENCES products(product_id) ON DELETE CASCADE
);

CREATE INDEX products_sku_idx ON products(sku);
CREATE INDEX products_upc_idx ON products(upc);
CREATE INDEX products_category_idx ON products(category);
CREATE INDEX products_name_idx ON products(name);
CREATE INDEX product_variants_sku_idx ON product_variants(sku);
CREATE INDEX product_variants_product_id_idx ON product_variants(product_id);



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
