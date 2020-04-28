package utils

import (
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/dbfv"
	"sync"
)

// Various goroutines, each running the protocol as a node, need to provide their AdditiveShare to
// a common accumulator. The last one unlocks "done", awaking the master thread.
type ConcurrentAdditiveShareAccum struct {
	*sync.Mutex
	*dbfv.AdditiveShare
	missing int
	done    *sync.Mutex
}

func NewConcurrentAdditiveShareAccum(params *bfv.Parameters, sigmaSmudging float64, nbParties int) *ConcurrentAdditiveShareAccum {
	c := &ConcurrentAdditiveShareAccum{
		Mutex:         &sync.Mutex{},
		AdditiveShare: dbfv.NewAdditiveShare(params.LogN, params.T),
		missing:       nbParties,
		done:          &sync.Mutex{},
	}

	c.done.Lock()
	return c
}

func (accum *ConcurrentAdditiveShareAccum) Accumulate(share *dbfv.AdditiveShare) {
	accum.Lock()
	defer accum.Unlock()

	dbfv.SumAdditiveShares(accum.AdditiveShare, share, accum.AdditiveShare)
	accum.missing -= 1
	if accum.missing == 0 {
		accum.done.Unlock()
	}
}

func (accum *ConcurrentAdditiveShareAccum) WaitDone() {
	accum.done.Lock()
}
