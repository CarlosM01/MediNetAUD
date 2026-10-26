package httpapi

import (
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/medinetcore/aud/internal/jwtauth"
)

// bearerScheme names the JWT security scheme in the OpenAPI document.
const bearerScheme = "bearer"

// bearerDetail is the same for every authentication failure, so the response never tells
// which part of the token was wrong.
const bearerDetail = "missing or invalid bearer token"

// metaRoles is the operation metadata key that lists the roles allowed to call it.
const metaRoles = "aud.roles"

type principalKey struct{}

// requireRoles authenticates the bearer token and checks that the caller holds one of the
// roles of the operation (metaRoles). It answers 401 for a missing or invalid token and 403
// for a valid token without the role. An operation without roles is denied to everyone.
func requireRoles(api huma.API, tokens *jwtauth.Verifier) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		raw, present := bearerToken(ctx.Header("Authorization"))
		principal, err := tokens.Verify(raw)
		if !present || err != nil {
			challenge := `Bearer realm="aud"`
			if present {
				challenge += `, error="invalid_token"`
			}
			ctx.SetHeader("WWW-Authenticate", challenge)
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, bearerDetail)
			return
		}

		roles, _ := ctx.Operation().Metadata[metaRoles].([]string)
		if len(roles) == 0 || !principal.HasAnyRole(roles...) {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "this operation requires one of the roles: "+strings.Join(roles, ", "))
			return
		}
		next(huma.WithValue(ctx, principalKey{}, principal))
	}
}

// bearerToken extracts the token from an "Authorization: Bearer <token>" header.
func bearerToken(header string) (string, bool) {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t") {
		return "", false
	}
	return token, true
}
