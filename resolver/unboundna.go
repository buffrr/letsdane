//go:build !unbound
// +build !unbound

package resolver

type Recursive struct {
	DefaultResolver
}

func NewRecursive() (r *Recursive, err error) {
	return nil, ErrUnboundNotAvail
}

func (r *Recursive) SetFwd(addr string) error {
	return ErrUnboundNotAvail
}

func (r *Recursive) ResolvConf(name string) error {
	return ErrUnboundNotAvail
}

func (r *Recursive) AddTA(ta string) error {
	return ErrUnboundNotAvail
}

func (r *Recursive) AddTAFile(file string) error {
	return ErrUnboundNotAvail
}

func (r *Recursive) Destroy() {
}
