package oidc

import (
	"context"

	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathGroupsList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "groups/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathGroupList,
		},

		HelpSynopsis:    pathGroupHelpSyn,
		HelpDescription: pathGroupHelpDesc,
	}
}

func pathGroups(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `groups/(?P<name>.+)`,
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the group inside the group claim.",
			},
			"policies": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Comma-separated list of policies associated to the group.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.DeleteOperation: b.pathGroupDelete,
			logical.ReadOperation:   b.pathGroupRead,
			logical.UpdateOperation: b.pathGroupWrite,
		},

		HelpSynopsis:    pathGroupHelpSyn,
		HelpDescription: pathGroupHelpDesc,
	}
}

func (b *backend) Group(ctx context.Context, s logical.Storage, n string) (*GroupEntry, error) {
	entry, err := s.Get(ctx, "group/"+n)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result GroupEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) pathGroupDelete(ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if len(name) == 0 {
		return logical.ErrorResponse("Error empty name"), nil
	}

	err := req.Storage.Delete(ctx, "group/"+name)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathGroupRead(ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if len(name) == 0 {
		return logical.ErrorResponse("Error empty name"), nil
	}

	group, err := b.Group(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"policies": group.Policies,
		},
	}, nil
}

func (b *backend) pathGroupWrite(ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if len(name) == 0 {
		return logical.ErrorResponse("Error empty name"), nil
	}

	entry, err := logical.StorageEntryJSON("group/"+name, &GroupEntry{
		Policies: policyutil.ParsePolicies(d.Get("policies").(string)),
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathGroupList(ctx context.Context,
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	groups, err := req.Storage.List(ctx, "group/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(groups), nil
}

type GroupEntry struct {
	Policies []string
}

const pathGroupHelpSyn = `
Manage users allowed to authenticate.
`

const pathGroupHelpDesc = `
This endpoint allows you to create, read, update, and delete configuration
for OpenID group claims that are allowed to authenticate, and associate policies to
them.
`
