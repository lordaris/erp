package dbtest

import (
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lordaris/erp/business/domain/homebus"
	"github.com/lordaris/erp/business/domain/homebus/stores/homedb"
	"github.com/lordaris/erp/business/domain/inventorybus"
	"github.com/lordaris/erp/business/domain/inventorybus/stores/inventorydb"
	"github.com/lordaris/erp/business/domain/productbus"
	"github.com/lordaris/erp/business/domain/productbus/stores/productdb"
	"github.com/lordaris/erp/business/domain/userbus"
	"github.com/lordaris/erp/business/domain/userbus/stores/usercache"
	"github.com/lordaris/erp/business/domain/userbus/stores/userdb"
	"github.com/lordaris/erp/business/domain/vproductbus"
	"github.com/lordaris/erp/business/domain/vproductbus/stores/vproductdb"
	"github.com/lordaris/erp/business/sdk/delegate"
	"github.com/lordaris/erp/foundation/logger"
)

// BusDomain represents all the business domain apis needed for testing.
type BusDomain struct {
	Delegate  *delegate.Delegate
	Home      *homebus.Business
	Product   *productbus.Business
	User      *userbus.Business
	VProduct  *vproductbus.Business
	Inventory *inventorybus.Business
}

func newBusDomains(log *logger.Logger, db *sqlx.DB) BusDomain {
	delegate := delegate.New(log)
	userBus := userbus.NewBusiness(log, delegate, usercache.NewStore(log, userdb.NewStore(log, db), time.Hour))
	productBus := productbus.NewBusiness(log, userBus, delegate, productdb.NewStore(log, db))
	homeBus := homebus.NewBusiness(log, userBus, delegate, homedb.NewStore(log, db))
	vproductBus := vproductbus.NewBusiness(vproductdb.NewStore(log, db))
	inventoryBus := inventorybus.NewBusiness(log, productBus, delegate, inventorydb.NewStore(log, db))

	return BusDomain{
		Delegate:  delegate,
		Home:      homeBus,
		Product:   productBus,
		User:      userBus,
		VProduct:  vproductBus,
		Inventory: inventoryBus,
	}
}
