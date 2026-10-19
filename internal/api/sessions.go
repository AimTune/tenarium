package api

import (
	"net"
	"net/http"

	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// clientInfo records the caller's user agent and address for the sessions
// a request opens.
func clientInfo(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		ctx := tenant.WithClient(r.Context(), tenant.ClientInfo{UserAgent: r.UserAgent(), IP: ip})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) listMySessions(w http.ResponseWriter, r *http.Request) {
	id, ok := selfID(w, r)
	if !ok {
		return
	}
	s.writeSessions(w, r, id)
}

func (s *Server) revokeMySession(w http.ResponseWriter, r *http.Request) {
	id, ok := selfID(w, r)
	if !ok {
		return
	}
	s.revokeSessionOf(w, r, id)
}

func (s *Server) listUserSessions(w http.ResponseWriter, r *http.Request) {
	if u, ok := s.loadUser(w, r, sdk.ActionUsersRead); ok {
		s.writeSessions(w, r, u.ID)
	}
}

func (s *Server) revokeUserSession(w http.ResponseWriter, r *http.Request) {
	if u, ok := s.loadUser(w, r, sdk.ActionUsersWrite); ok {
		s.revokeSessionOf(w, r, u.ID)
	}
}

func (s *Server) writeSessions(w http.ResponseWriter, r *http.Request, userID string) {
	ss, err := s.Tenants.ListSessions(r.Context(), userID)
	if err != nil {
		s.writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nonNil(ss)})
}

func (s *Server) revokeSessionOf(w http.ResponseWriter, r *http.Request, userID string) {
	if err := s.Tenants.RevokeSession(r.Context(), userID, r.PathValue("session")); err != nil {
		s.writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) requestMagicLink(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email  string `json:"email"`
		Tenant string `json:"tenant"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := s.Tenants.RequestMagicLink(r.Context(), in.Email, in.Tenant); err != nil {
		s.writeAuthErr(w, r, err)
		return
	}
	// Same answer whether or not the address is known.
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "sent if the account exists"})
}

func (s *Server) requestEmailChange(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	id, ok := selfID(w, r)
	if !ok {
		return
	}
	if err := s.Tenants.RequestEmailChange(r.Context(), id, in.Email, in.Password); err != nil {
		s.writeAuthErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "confirmation sent to the new address"})
}

func (s *Server) confirmEmailChange(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if !decode(w, r, &in) {
		return
	}
	u, err := s.Tenants.ConfirmEmailChange(r.Context(), in.Token)
	if err != nil {
		s.writeAuthErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, u)
}
