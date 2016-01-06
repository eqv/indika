package data_structures

import (
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"github.com/go-errors/errors"
)

type State interface {
  Apply(mu *uc.Unicorn) *errors.Error
  Extract(mu *uc.Unicorn) *errors.Error
}
