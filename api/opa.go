package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/render"
	"github.com/open-policy-agent/opa/rego"
)

type OPA struct {
	module *rego.Rego
}

func (s *server) opaMW() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			path := strings.Split(strings.Trim(r.URL.Path, "/"), "/")

			// set OPA input
			input := map[string]interface{}{
				"method": r.Method,
				"path":   path,
			}

			s.opa.module = rego.New(
				rego.Query(s.v.GetString(ConfigOpaQuery)),
				rego.Load([]string{s.v.GetString(ConfigOpaFilePath)}, nil))

			// prepare for evaluation
			query, err := s.opa.module.PrepareForEval(ctx)
			if err != nil {
				render.Render(w, r, ErrServerError(r, errors.New("failed to prepare for evaluating authz policies; "+err.Error())))
				return
			}

			// evaluate the query with input
			res, err := query.Eval(ctx, rego.EvalInput(input))
			if err != nil {
				render.Render(w, r, ErrServerError(r, errors.New("failed to evaluate authz policies; "+err.Error())))
				return
			}

			// exception : the result set is empty
			if len(res) == 0 {
				render.Render(w, r, ErrServerError(r, errors.New("failed to authorize (undefined query)")))
				return
			}

			// get the decision
			allowed, ok := res[0].Bindings[s.v.GetString(ConfigOpaDecisionKey)].(bool)

			// exception : query result is not boolean type
			if !ok {
				render.Render(w, r, ErrServerError(r, errors.New("failed to authorize (unexpected query result type)")))
				return
			}

			// if not allowed
			if !allowed {
				render.Render(w, r, ErrUnauthorized(r, errors.New("not allowed")))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
