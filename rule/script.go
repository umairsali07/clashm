package rules

import (
	"github.com/phuslu/log"

	C "github.com/umairsali07/clashm/constant"
)

type Script struct {
	*Base
	matcher  C.Matcher
	shortcut string
	adapter  string
}

func (s *Script) RuleType() C.RuleType {
	return C.Script
}

func (s *Script) Match(metadata *C.Metadata) bool {
	rs, err := s.matcher.Match(metadata)
	if err != nil {
		log.Warn().Err(err).Str("name", s.matcher.Name()).Msg("[Matcher] match shortcut failed")
		return false
	}

	return rs
}

func (s *Script) Adapter() string {
	return s.adapter
}

func (s *Script) Payload() string {
	return s.shortcut
}

func (s *Script) ShouldResolveIP() bool {
	return false
}

func (s *Script) RuleExtra() *C.RuleExtra {
	return nil
}

func (s *Script) SetMatcher(m C.Matcher) {
	s.matcher = m
}

func NewScript(shortcut string, adapter string) (*Script, error) {
	obj := &Script{
		Base:     &Base{},
		shortcut: shortcut,
		adapter:  adapter,
	}

	return obj, nil
}

var _ C.Rule = (*Script)(nil)
