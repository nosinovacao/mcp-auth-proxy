package repository

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/pkce"
)

type Repository interface {
	fosite.Storage
	oauth2.CoreStorage
	oauth2.TokenRevocationStorage
	pkce.PKCERequestStorage
	DynamicClientStorage
	AuthorizeRequestStorage
	Close() error
}

type DynamicClientStorage interface {
	RegisterClient(ctx context.Context, client fosite.Client) error
}

type AuthorizeRequestStorage interface {
	CreateAuthorizeRequest(ctx context.Context, request fosite.AuthorizeRequester) error
	GetAuthorizeRequest(ctx context.Context, requestID string) (fosite.AuthorizeRequester, error)
	DeleteAuthorizeRequest(ctx context.Context, requestID string) error
}

func restoreSession(req *fosite.Request, sessionData json.RawMessage, sess fosite.Session) error {
	if len(sessionData) > 0 && sess != nil {
		if err := json.Unmarshal(sessionData, sess); err != nil {
			return fmt.Errorf("failed to unmarshal session data: %w", err)
		}
		req.SetSession(sess)
	}
	return nil
}
