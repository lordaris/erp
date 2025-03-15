package dbtest

import (
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lordaris/erp/business/domain/productbus"
	"github.com/lordaris/erp/business/domain/productbus/stores/productdb"
	"github.com/lordaris/erp/business/domain/userbus"
	"github.com/lordaris/erp/business/domain/userbus/stores/usercache"
	"github.com/lordaris/erp/business/domain/userbus/stores/userdb"
	"github.com/lordaris/erp/business/sdk/delegate"
	"github.com/lordaris/erp/foundation/logger"
)

// BusDomain represents all the business domain apis needed for testing.
type BusDomain struct {
	Delegate *delegate.Delegate
	Product  *productbus.Business
	User     *userbus.Business
}

func newBusDomains(log *logger.Logger, db *sqlx.DB) BusDomain {
	delegate := delegate.New(log)
	userBus := userbus.NewBusiness(log, delegate, usercache.NewStore(log, userdb.NewStore(log, db), time.Hour))
	productBus := productbus.NewBusiness(log, delegate, productdb.NewStore(db))

	return BusDomain{
		Delegate: delegate,
		Product:  productBus,
		User:     userBus,
	}
}
