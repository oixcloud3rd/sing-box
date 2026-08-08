package domainevaluator

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	serviceDomainEvaluator "github.com/sagernet/sing-box/service/domain_evaluator"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.DomainEvaluatorManager = (*Manager)(nil)

type Manager struct {
	evaluators []adapter.DomainEvaluator
	services   []*serviceDomainEvaluator.Evaluator
	byTag      map[string]adapter.DomainEvaluator
}

func NewManager(
	ctx context.Context,
	logger log.ContextLogger,
	dnsRouter adapter.DNSRouter,
	dnsTransportManager adapter.DNSTransportManager,
	options []option.DomainEvaluatorOptions,
) *Manager {
	manager := &Manager{
		byTag: make(map[string]adapter.DomainEvaluator, len(options)),
	}
	for _, evaluatorOptions := range options {
		evaluator := serviceDomainEvaluator.New(ctx, logger, dnsRouter, dnsTransportManager, evaluatorOptions)
		manager.evaluators = append(manager.evaluators, evaluator)
		manager.services = append(manager.services, evaluator)
		manager.byTag[evaluatorOptions.Tag] = evaluator
	}
	return manager
}

func (m *Manager) Start(stage adapter.StartStage) error {
	for _, evaluator := range m.services {
		if err := evaluator.Start(stage); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) Close() error {
	var err error
	for _, evaluator := range m.services {
		err = E.Append(err, evaluator.Close(), func(err error) error {
			return E.Cause(err, "close domain evaluator[", evaluator.Tag(), "]")
		})
	}
	return err
}

func (m *Manager) DomainEvaluators() []adapter.DomainEvaluator {
	return append([]adapter.DomainEvaluator(nil), m.evaluators...)
}

func (m *Manager) Get(tag string) (adapter.DomainEvaluator, bool) {
	evaluator, loaded := m.byTag[tag]
	return evaluator, loaded
}
