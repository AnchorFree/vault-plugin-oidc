package oidc

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// Factory returns a new backend as logical.Backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// FactoryType is a wrapper func that allows the Factory func to specify
// the backend type for the mock backend plugin instance.
func FactoryType(backendType logical.BackendType) logical.Factory {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		b := Backend()
		b.BackendType = backendType
		if err := b.Setup(ctx, conf); err != nil {
			return nil, err
		}
		return b, nil
	}
}

// Backend returns a private embedded struct of framework.Backend.
func Backend() *backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		//PeriodicFunc periodicFunc
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(&b),
				pathUsers(&b),
				pathGroups(&b),
				pathUsersList(&b),
				pathGroupsList(&b),
				pathLogin(&b),
			},
		),
		AuthRenew: nil, // explicitly don't support renewal.
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
		},
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
	}
	return &b
}

type backend struct {
	*framework.Backend
}

const backendHelp = `
The OpenID Connect provider allows Vault to issue Tokens for
holders of OpenID Connect identity tokens, which are self validating.

Only users that have an explicit mapping of username or group to a policy
will be granted Tokens.
`
