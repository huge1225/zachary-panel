package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"nexus-panel/internal/master/hub"
	"nexus-panel/internal/master/model"
	"nexus-panel/internal/master/service"
)

func setupTestServer(t *testing.T) (*gin.Engine, func()) {
	t.Helper()
	r, _, cleanup := setupTestServerWithDB(t)
	return r, cleanup
}

func setupTestServerWithDB(t *testing.T) (*gin.Engine, *gorm.DB, func()) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	// Demo seed data (users / nodes / tunnels) is opt-in; credentials come from env in tests.
	t.Setenv("NEXUS_SEED_DEMO", "true")
	t.Setenv("NEXUS_ADMIN_PASSWORD", "admin123")
	t.Setenv("NEXUS_DEMO_USER_PASSWORD", "user12345")

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_nexus.db")
	db, err := model.InitDB("sqlite", dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	agentHub := hub.NewAgentHub(db)
	orch := service.NewOrchestrator(db, agentHub)
	srv := NewServer(db, agentHub, orch)
	return srv.SetupRouter(), db, func() {
		_ = os.RemoveAll(tmpDir)
	}
}

func loginAndGetToken(t *testing.T, r *gin.Engine, email, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login failed for %s: status=%d body=%s", email, w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Token == "" {
		t.Fatalf("invalid login response: %v", err)
	}
	return resp.Token
}

func TestRBACAndTunnelPermissionBoundaries(t *testing.T) {
	r, cleanup := setupTestServer(t)
	defer cleanup()

	// 1. 验证预置的两套账号均可登录
	adminToken := loginAndGetToken(t, r, "admin@nexus.local", "admin123")
	userToken := loginAndGetToken(t, r, "user@nexus.local", "user12345")

	// 2. 垂直越权拦截测试：普通用户访问 /api/v1/admin/* 全部返回 403
	adminEndpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/admin/settings"},
		{http.MethodPut, "/api/v1/admin/settings"},
		{http.MethodPost, "/api/v1/admin/nodes"},
		{http.MethodPost, "/api/v1/admin/lines"},
		{http.MethodPost, "/api/v1/admin/roles"},
		{http.MethodPost, "/api/v1/admin/plans"},
		{http.MethodGet, "/api/v1/admin/users"},
		{http.MethodPost, "/api/v1/admin/users"},
	}
	for _, ep := range adminEndpoints {
		req := httptest.NewRequest(ep.method, ep.path, bytes.NewReader([]byte(`{}`)))
		req.Header.Set("Authorization", "Bearer "+userToken)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for normal user on %s %s, got %d", ep.method, ep.path, w.Code)
		}
	}

	// 3. 角色与套餐初始绑定验证：
	//    预置角色 #1 (标准角色 -> 隧道 "1")，角色 #2 (VIP 专线角色 -> 隧道 "1,2")
	//    预置套餐 #1 绑定角色 #1，套餐 #2 绑定角色 #2
	//    普通用户初始分配套餐 #1 与角色 #1，仅能看到隧道 #1
	{
		req := httptest.NewRequest(http.MethodGet, "/api/v1/lines", nil)
		req.Header.Set("Authorization", "Bearer "+userToken)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("GET /api/v1/lines failed: %d", w.Code)
		}
		var userLines []model.TunnelLine
		_ = json.Unmarshal(w.Body.Bytes(), &userLines)
		if len(userLines) != 1 || userLines[0].ID != 1 {
			t.Fatalf("expected user with RoleGroup #1 to only see tunnel #1, got %+v", userLines)
		}
	}

	// 4. 隧道越权创建拦截：普通用户尝试在当前角色未授权的隧道 #2 创建规则 -> 403 Forbidden
	{
		unauthRule, _ := json.Marshal(map[string]any{
			"name":           "越权使用隧道2",
			"tunnel_line_id": 2,
			"protocol":       "tcp",
			"targets":        []map[string]string{{"address": "8.8.8.8:53"}},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(unauthRule))
		req.Header.Set("Authorization", "Bearer "+userToken)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 when user creates rule on unauthorized tunnel #2, got %d (%s)", w.Code, w.Body.String())
		}
	}

	// 5. 普通用户在当前角色授权的隧道 #1 创建规则 -> 201 Created
	var userRuleID uint64
	{
		authRule, _ := json.Marshal(map[string]any{
			"name":           "合规规则-隧道1",
			"tunnel_line_id": 1,
			"protocol":       "tcp",
			"targets":        []map[string]string{{"address": "1.1.1.1:443"}},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(authRule))
		req.Header.Set("Authorization", "Bearer "+userToken)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201 when user creates rule on authorized tunnel #1, got %d (%s)", w.Code, w.Body.String())
		}
		var created model.ForwardRule
		_ = json.Unmarshal(w.Body.Bytes(), &created)
		userRuleID = created.ID
	}

	// 6. 水平越权拦截：普通用户尝试编辑/删除管理员的规则 -> 403 Forbidden
	{
		adminRule, _ := json.Marshal(map[string]any{
			"name":           "管理员规则",
			"tunnel_line_id": 1,
			"protocol":       "tcp",
			"targets":        []map[string]string{{"address": "1.0.0.1:443"}},
		})
		cReq := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(adminRule))
		cReq.Header.Set("Authorization", "Bearer "+adminToken)
		cReq.Header.Set("Content-Type", "application/json")
		cw := httptest.NewRecorder()
		r.ServeHTTP(cw, cReq)
		if cw.Code != http.StatusCreated {
			t.Fatalf("admin create rule failed: %d (%s)", cw.Code, cw.Body.String())
		}
		var adminCreated model.ForwardRule
		_ = json.Unmarshal(cw.Body.Bytes(), &adminCreated)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/rules/"+uintToStr(adminCreated.ID), nil)
		req.Header.Set("Authorization", "Bearer "+userToken)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 when user tries to delete admin rule #1, got %d", w.Code)
		}
	}

	// 7. 套餐购买自动升级角色与隧道：普通用户购买套餐 #2 (绑定 VIP 专线角色 #2) 后，自动获得隧道 #2 权限
	{
		req := httptest.NewRequest(http.MethodPost, "/api/v1/plans/2/purchase", nil)
		req.Header.Set("Authorization", "Bearer "+userToken)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 when purchasing plan #2, got %d (%s)", w.Code, w.Body.String())
		}

		// 升级后可在隧道 #2 创建规则 -> 201 Created
		vipRule, _ := json.Marshal(map[string]any{
			"name":           "VIP角色规则-隧道2",
			"tunnel_line_id": 2,
			"protocol":       "tcp",
			"targets":        []map[string]string{{"address": "8.8.8.8:53"}},
		})
		rReq := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(vipRule))
		rReq.Header.Set("Authorization", "Bearer "+userToken)
		rReq.Header.Set("Content-Type", "application/json")
		rw := httptest.NewRecorder()
		r.ServeHTTP(rw, rReq)
		if rw.Code != http.StatusCreated {
			t.Fatalf("expected 201 on tunnel #2 after upgrading to Plan #2 / RoleGroup #2, got %d (%s)", rw.Code, rw.Body.String())
		}
	}

	// 8. 角色级联权限回收：管理员修改角色 #2 的可用隧道为空（或管理员将用户切回无隧道角色）后，
	//    绑定该角色的套餐与用户权限同步收缩，且该用户的存量规则自动暂停并禁止再次开启
	{
		roleUpdate, _ := json.Marshal(map[string]any{
			"name":            "VIP 专线角色",
			"allowed_tunnels": "",
		})
		req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/roles/2", bytes.NewReader(roleUpdate))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("admin update role #2 allowed_tunnels failed: %d (%s)", w.Code, w.Body.String())
		}

		// 普通用户尝试重新启用规则 -> 403 Forbidden
		toggleReq := httptest.NewRequest(http.MethodPost, "/api/v1/rules/"+uintToStr(userRuleID)+"/toggle", nil)
		toggleReq.Header.Set("Authorization", "Bearer "+userToken)
		tw := httptest.NewRecorder()
		r.ServeHTTP(tw, toggleReq)
		if tw.Code != http.StatusForbidden {
			t.Fatalf("expected 403 when toggling rule after role tunnel revocation, got %d (%s)", tw.Code, tw.Body.String())
		}
	}
}

func uintToStr(v uint64) string {
	b, _ := json.Marshal(v)
	return string(b)
}
