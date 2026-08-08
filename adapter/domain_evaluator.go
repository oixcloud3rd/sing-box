package adapter

import "context"

type DomainEvaluator interface {
	Tag() string
	Evaluate(ctx context.Context, metadata *InboundContext, domain string) bool
}

type DomainEvaluatorManager interface {
	Lifecycle
	DomainEvaluators() []DomainEvaluator
	Get(tag string) (DomainEvaluator, bool)
}
