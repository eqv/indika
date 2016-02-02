package blanket_emulator

import (
	log "github.com/Sirupsen/logrus"
	"github.com/go-errors/errors"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

const pagesize = 4096
const log_mem = true

type WorkingSet struct {
	mapped []uint64
	newest int
	oldest int
}

func NewWorkingSet(size int) *WorkingSet {
	res := new(WorkingSet)
	res.mapped = make([]uint64, size)
	res.newest = -1
	res.oldest = -1
	return res
}

func (s *WorkingSet) Map(addr, size uint64, em *Emulator) *errors.Error {
	if log_mem {
		log.WithFields(log.Fields{"addr": hex(addr), "size": size}).Debug("Map Memory")
	}
	alignment := (addr % pagesize)
	base_addr := addr - alignment
	if log_mem {
		log.WithFields(log.Fields{"base_addr": hex(base_addr), "size": uint64(pagesize)}).Debug("Map Memory called")
	}
	err := em.mu.MemMapProt(base_addr, uint64(pagesize), uc.PROT_READ|uc.PROT_WRITE)
	if err != nil {
		return wrap(err)
	}
	mem := em.Env.GetMem(base_addr, pagesize)
	if log_mem {
		log.WithFields(log.Fields{"mem": mem[0:8]}).Debug("Memory written")
	}
	err = em.mu.MemWrite(base_addr, mem)
	mem2, err := em.mu.MemRead(base_addr, pagesize)
	if err != nil {
		return wrap(err)
	}
	if log_mem {
		log.WithFields(log.Fields{"mem": mem2[0:8]}).Debug("Memory read")
	}
	if err != nil {
		return wrap(err)
	}
	s.StoreInWorkingSet(base_addr, em.mu)
	if addr+size > base_addr+pagesize { //sometimes we might need to map 2 pages
		s.Map(base_addr+pagesize, 1, em) //map next pages as well
	}
	return nil
}

func (s *WorkingSet) StoreInWorkingSet(addr uint64, mu uc.Unicorn) *errors.Error {
	if log_mem {
		log.WithFields(log.Fields{"addr": hex(addr)}).Debug("Store In Working Set")
	}
	if s.newest == -1 {
		s.mapped[0] = addr
		s.oldest = 0
		s.newest = 0
	}
	s.newest = (s.newest + 1) % len(s.mapped)
	if s.newest == s.oldest { // unmap old page
		addr_to_unmap := s.mapped[s.oldest]
		if log_mem {
			log.WithFields(log.Fields{"addr_to_unmap": addr_to_unmap}).Debug("unmap")
		}
		err := mu.MemUnmap(addr_to_unmap, pagesize)
		if err != nil {
			return wrap(err)
		}
	}
	s.oldest = (s.oldest + 1) % len(s.mapped)
	s.mapped[s.newest] = addr
	return nil
}

func (s *WorkingSet) Clear(mu uc.Unicorn) *errors.Error {
	if s.newest == -1 {
		return nil
	}
	for i := s.oldest; i != s.newest; i = (i + 1) % len(s.mapped) {
		err := mu.MemUnmap(s.mapped[i], pagesize)
		if err != nil {
			return wrap(err)
		}
	}
	return nil
}
