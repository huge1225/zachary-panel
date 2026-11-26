package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"nexus-panel/internal/master/model"
	"nexus-panel/pkg/utils"
)

// couponClaimMu serializes coupon usage checks and atomic claim updates so concurrent requests
// from the same user cannot race past PerUserLimit on SQLite/Postgres/MySQL.
var couponClaimMu sync.Mutex

const (
	maxCouponValueCents   int64 = 100_000_000 // ¥1,000,000 cap
	maxWithdrawAmountCent int64 = 100_000_000 // ¥1,000,000 cap
	maxOpenTicketsPerUser int64 = 20
)

func normalizeCouponCode(raw string) string {
	return strings.ToUpper(strings.TrimSpace(raw))
}

func isValidCouponCode(code string) bool {
	if len(code) < 3 || len(code) > 48 {
		return false
	}
	for i := 0; i < len(code); i++ {
		ch := code[i]
		if (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
			continue
		}
		return false
	}
	return true
}

func normalizeInviteCode(raw string) string {
	return strings.ToUpper(strings.TrimSpace(raw))
}

func isValidInviteCodeFormat(code string) bool {
	if len(code) < 4 || len(code) > 32 {
		return false
	}
	for i := 0; i < len(code); i++ {
		ch := code[i]
		if (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
			continue
		}
		return false
	}
	return true
}

func sanitizeCleanText(raw string, maxBytes int) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		if r == '\n' || r == '\t' || (r >= 0x20 && r != 0x7f) {
			b.WriteRune(r)
		}
	}
	return truncateUTF8(strings.TrimSpace(b.String()), maxBytes)
}

func sanitizeSingleLine(raw string, maxBytes int) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		if r >= 0x20 && r != 0x7f && r != '\r' && r != '\n' {
			b.WriteRune(r)
		}
	}
	return truncateUTF8(strings.TrimSpace(b.String()), maxBytes)
}

func couponAllowsPlan(allowedPlanIDs string, planID uint64) bool {
	raw := strings.TrimSpace(allowedPlanIDs)
	if raw == "" || raw == "*" {
		return true
	}
	target := strconv.FormatUint(planID, 10)
	for _, part := range strings.Split(raw, ",") {
		if strings.TrimSpace(part) == target {
			return true
		}
	}
	return false
}

func normalizeAllowedPlanIDs(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "*" {
		return "", nil
	}
	var cleaned []string
	seen := make(map[uint64]struct{})
	for _, p := range strings.Split(trimmed, ",") {
		tok := strings.TrimSpace(p)
		if tok == "" {
			continue
		}
		id, err := strconv.ParseUint(tok, 10, 64)
		if err != nil || id == 0 {
			return "", fmt.Errorf("限定套餐 ID 格式无效")
		}
		if _, dup := seen[id]; !dup {
			seen[id] = struct{}{}
			cleaned = append(cleaned, strconv.FormatUint(id, 10))
		}
	}
	return strings.Join(cleaned, ","), nil
}

type couponQuote struct {
	Coupon        model.Coupon `json:"coupon"`
	OriginalCents int64        `json:"original_cents"`
	DiscountCents int64        `json:"discount_cents"`
	PayableCents  int64        `json:"payable_cents"`
}

func evaluateCouponQuote(db *gorm.DB, uid uint64, code string, plan *model.Plan, now time.Time) (*couponQuote, error) {
	norm := normalizeCouponCode(code)
	if norm == "" || !isValidCouponCode(norm) {
		return nil, fmt.Errorf("优惠券码无效或不存在")
	}
	if plan == nil || plan.PriceCents <= 0 {
		return nil, fmt.Errorf("免费套餐不支持使用优惠券")
	}

	var cp model.Coupon
	if err := db.Where("code = ?", norm).First(&cp).Error; err != nil {
		return nil, fmt.Errorf("优惠券码无效或不存在")
	}
	if !cp.Active {
		return nil, fmt.Errorf("该优惠券已停用")
	}
	if cp.StartsAt != nil && !cp.StartsAt.IsZero() && now.Before(*cp.StartsAt) {
		return nil, fmt.Errorf("该优惠券尚未到生效时间")
	}
	if cp.EndsAt != nil && !cp.EndsAt.IsZero() && now.After(*cp.EndsAt) {
		return nil, fmt.Errorf("该优惠券已过期")
	}
	if cp.MaxUses > 0 && cp.UsedCount >= cp.MaxUses {
		return nil, fmt.Errorf("该优惠券已被领完")
	}
	if !couponAllowsPlan(cp.AllowedPlanIDs, plan.ID) {
		return nil, fmt.Errorf("该优惠券不适用于当前所选套餐")
	}
	if cp.MinSpendCents > 0 && plan.PriceCents < cp.MinSpendCents {
		return nil, fmt.Errorf("订单金额未满 ¥%.2f，无法使用该优惠券", float64(cp.MinSpendCents)/100.0)
	}
	if cp.PerUserLimit > 0 && uid > 0 {
		var usedByUser int64
		db.Model(&model.CouponRedemption{}).
			Where("coupon_id = ? AND user_id = ?", cp.ID, uid).
			Count(&usedByUser)
		if usedByUser >= int64(cp.PerUserLimit) {
			return nil, fmt.Errorf("您对该优惠券的使用次数已达上限 (%d 次)", cp.PerUserLimit)
		}
	}

	orig := plan.PriceCents
	var discount int64
	switch cp.Type {
	case "percent":
		if cp.Value <= 0 || cp.Value > 100 {
			return nil, fmt.Errorf("优惠券折扣配置异常")
		}
		discount = int64(math.Round(float64(orig) * float64(cp.Value) / 100.0))
		if cp.MaxDiscountCents > 0 && discount > cp.MaxDiscountCents {
			discount = cp.MaxDiscountCents
		}
	case "fixed":
		if cp.Value <= 0 {
			return nil, fmt.Errorf("优惠券满减配置异常")
		}
		discount = cp.Value
	default:
		return nil, fmt.Errorf("未知的优惠券类型")
	}
	if discount < 0 {
		discount = 0
	}
	if discount > orig {
		discount = orig
	}
	payable := orig - discount
	return &couponQuote{
		Coupon:        cp,
		OriginalCents: orig,
		DiscountCents: discount,
		PayableCents:  payable,
	}, nil
}

// readOptionalCouponCode safely extracts an optional {"coupon_code": "..."} body while tolerating empty/nil bodies.
func readOptionalCouponCode(c *gin.Context) (string, int, error) {
	if c.Request == nil || c.Request.Body == nil || c.Request.Body == http.NoBody {
		return normalizeCouponCode(c.Query("coupon_code")), 0, nil
	}
	raw, err := io.ReadAll(c.Request.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return "", http.StatusRequestEntityTooLarge, fmt.Errorf("请求体超过大小限制")
		}
		return "", http.StatusBadRequest, fmt.Errorf("读取请求参数失败")
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return normalizeCouponCode(c.Query("coupon_code")), 0, nil
	}
	var payload struct {
		CouponCode string `json:"coupon_code"`
	}
	if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
		return "", http.StatusBadRequest, fmt.Errorf("请求参数 JSON 格式错误")
	}
	return normalizeCouponCode(payload.CouponCode), 0, nil
}

// claimCouponInTx validates and atomically consumes 1 usage of a coupon inside an active transaction.
// Caller MUST hold couponClaimMu when couponCode != "".
func claimCouponInTx(tx *gorm.DB, uid uint64, userEmail, couponCode, scene, orderNo string, plan *model.Plan, now time.Time) (*couponQuote, error) {
	quote, err := evaluateCouponQuote(tx, uid, couponCode, plan, now)
	if err != nil {
		return nil, fmt.Errorf("coupon_invalid:%s", err.Error())
	}
	res := tx.Model(&model.Coupon{}).
		Where("id = ? AND active = ? AND (max_uses = 0 OR used_count < max_uses)", quote.Coupon.ID, true).
		Update("used_count", gorm.Expr("used_count + 1"))
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, fmt.Errorf("coupon_invalid:该优惠券已被领完或已停用")
	}
	rec := model.CouponRedemption{
		CouponID:      quote.Coupon.ID,
		CouponCode:    quote.Coupon.Code,
		UserID:        uid,
		UserEmail:     userEmail,
		OrderNo:       orderNo,
		Scene:         scene,
		PlanID:        plan.ID,
		OriginalCents: quote.OriginalCents,
		DiscountCents: quote.DiscountCents,
		PayableCents:  quote.PayableCents,
		CreatedAt:     now,
	}
	if err := tx.Create(&rec).Error; err != nil {
		return nil, err
	}
	return quote, nil
}

// POST /api/v1/coupons/preview
func (s *Server) handlePreviewCoupon(c *gin.Context) {
	var req struct {
		Code   string `json:"code" binding:"required"`
		PlanID uint64 `json:"plan_id"`
		Scene  string `json:"scene"` // "plan_purchase" | "plan_reset"
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请输入优惠券码"})
		return
	}
	uid := s.currentUserID(c)
	planID := req.PlanID
	if req.Scene == "plan_reset" && planID == 0 {
		var u model.User
		if err := s.db.Select("id, plan_id").First(&u, uid).Error; err == nil {
			planID = u.PlanID
		}
	}
	if planID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请先选择套餐"})
		return
	}
	var plan model.Plan
	if err := s.db.First(&plan, planID).Error; err != nil || !plan.Active {
		c.JSON(http.StatusNotFound, gin.H{"error": "套餐不存在或已下架"})
		return
	}
	quote, err := evaluateCouponQuote(s.db, uid, req.Code, &plan, time.Now())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"valid":          true,
		"coupon_id":      quote.Coupon.ID,
		"coupon_code":    quote.Coupon.Code,
		"name":           quote.Coupon.Name,
		"type":           quote.Coupon.Type,
		"value":          quote.Coupon.Value,
		"original_cents": quote.OriginalCents,
		"discount_cents": quote.DiscountCents,
		"payable_cents":  quote.PayableCents,
	})
}

// GET /api/v1/admin/coupons
func (s *Server) handleAdminListCoupons(c *gin.Context) {
	query := s.db.Model(&model.Coupon{})
	if q := strings.TrimSpace(c.Query("q")); q != "" {
		upperLike := buildSafeLike(strings.ToUpper(q))
		rawLike := buildSafeLike(q)
		query = query.Where(`(code LIKE ? ESCAPE '!' OR name LIKE ? ESCAPE '!')`, upperLike, rawLike)
	}
	var total int64
	query.Count(&total)
	page, pageSize, pagedEnvelope := parseListPagination(c, 200, 500)
	var coupons []model.Coupon
	query.Order("id desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&coupons)
	respondListPayload(c, coupons, total, page, pageSize, pagedEnvelope)
}

type adminCouponReq struct {
	Code             string `json:"code"`
	Name             string `json:"name"`
	Type             string `json:"type"` // "percent" | "fixed"
	Value            int64  `json:"value"`
	MinSpendCents    int64  `json:"min_spend_cents"`
	MaxDiscountCents int64  `json:"max_discount_cents"`
	AllowedPlanIDs   string `json:"allowed_plan_ids"`
	StartsAt         string `json:"starts_at"`
	EndsAt           string `json:"ends_at"`
	MaxUses          int    `json:"max_uses"`
	PerUserLimit     *int   `json:"per_user_limit"`
	Active           *bool  `json:"active"`
}

func parseOptionalCouponTime(raw string) (*time.Time, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, nil
	}
	t, err := parseFlexibleExpireTime(s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// POST /api/v1/admin/coupons
func (s *Server) handleAdminCreateCoupon(c *gin.Context) {
	var req adminCouponReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请填写完整的优惠券配置"})
		return
	}
	code := normalizeCouponCode(req.Code)
	if code == "" {
		code = "CPN" + strings.ToUpper(utils.GenerateRandomToken(4))
	}
	if !isValidCouponCode(code) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "优惠券码需为 3-48 位字母、数字、连字符或下划线"})
		return
	}
	name := sanitizeSingleLine(req.Name, 128)
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请输入优惠券名称"})
		return
	}
	tp := strings.ToLower(strings.TrimSpace(req.Type))
	if tp != "percent" && tp != "fixed" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "优惠券类型必须为 percent (百分比折扣) 或 fixed (固定满减)"})
		return
	}
	if tp == "percent" && (req.Value < 1 || req.Value > 100) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "百分比折扣比例需在 1 - 100 之间（如 20 表示减免 20%）"})
		return
	}
	if tp == "fixed" && (req.Value < 1 || req.Value > maxCouponValueCents) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "固定减免金额需大于 0 且不超过上限"})
		return
	}
	if req.MinSpendCents < 0 || req.MinSpendCents > maxCouponValueCents || req.MaxDiscountCents < 0 || req.MaxDiscountCents > maxCouponValueCents {
		c.JSON(http.StatusBadRequest, gin.H{"error": "门槛或封顶金额超出有效范围"})
		return
	}
	if req.MaxUses < 0 || req.MaxUses > 10000000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "总可用次数超出有效范围"})
		return
	}
	allowedPlans, err := normalizeAllowedPlanIDs(req.AllowedPlanIDs)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	startsAt, err := parseOptionalCouponTime(req.StartsAt)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "生效时间格式无效"})
		return
	}
	endsAt, err := parseOptionalCouponTime(req.EndsAt)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "失效时间格式无效"})
		return
	}
	if startsAt != nil && endsAt != nil && endsAt.Before(*startsAt) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "失效时间不能早于生效时间"})
		return
	}
	perUser := 1
	if req.PerUserLimit != nil {
		if *req.PerUserLimit < 0 || *req.PerUserLimit > 100000 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "单用户限用次数超出有效范围"})
			return
		}
		perUser = *req.PerUserLimit
	}
	active := true
	if req.Active != nil {
		active = *req.Active
	}

	var dup int64
	s.db.Model(&model.Coupon{}).Where("code = ?", code).Count(&dup)
	if dup > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "该优惠券码已存在"})
		return
	}

	cp := model.Coupon{
		Code:             code,
		Name:             name,
		Type:             tp,
		Value:            req.Value,
		MinSpendCents:    req.MinSpendCents,
		MaxDiscountCents: req.MaxDiscountCents,
		AllowedPlanIDs:   allowedPlans,
		StartsAt:         startsAt,
		EndsAt:           endsAt,
		MaxUses:          req.MaxUses,
		PerUserLimit:     perUser,
		Active:           active,
	}
	if err := s.db.Create(&cp).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建优惠券失败"})
		return
	}
	s.recordAudit(c, "admin.create_coupon", cp.Code, fmt.Sprintf("创建优惠券 %s (%s=%d)", cp.Name, cp.Type, cp.Value))
	c.JSON(http.StatusCreated, cp)
}

// PUT /api/v1/admin/coupons/:id
func (s *Server) handleAdminUpdateCoupon(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid coupon id"})
		return
	}
	var cp model.Coupon
	if err := s.db.First(&cp, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "优惠券不存在"})
		return
	}
	var req adminCouponReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Name) != "" {
		cp.Name = sanitizeSingleLine(req.Name, 128)
	}
	if strings.TrimSpace(req.Type) != "" {
		tp := strings.ToLower(strings.TrimSpace(req.Type))
		if tp != "percent" && tp != "fixed" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的优惠券类型"})
			return
		}
		cp.Type = tp
	}
	if req.Value > 0 {
		cp.Value = req.Value
	}
	if cp.Type == "percent" && (cp.Value < 1 || cp.Value > 100) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "百分比折扣比例需在 1 - 100 之间"})
		return
	}
	if cp.Type == "fixed" && (cp.Value < 1 || cp.Value > maxCouponValueCents) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "固定减免金额超出有效范围"})
		return
	}
	if req.MinSpendCents >= 0 && req.MinSpendCents <= maxCouponValueCents {
		cp.MinSpendCents = req.MinSpendCents
	}
	if req.MaxDiscountCents >= 0 && req.MaxDiscountCents <= maxCouponValueCents {
		cp.MaxDiscountCents = req.MaxDiscountCents
	}
	allowedPlans, err := normalizeAllowedPlanIDs(req.AllowedPlanIDs)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cp.AllowedPlanIDs = allowedPlans

	startsAt, err := parseOptionalCouponTime(req.StartsAt)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "生效时间格式无效"})
		return
	}
	endsAt, err := parseOptionalCouponTime(req.EndsAt)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "失效时间格式无效"})
		return
	}
	if startsAt != nil && endsAt != nil && endsAt.Before(*startsAt) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "失效时间不能早于生效时间"})
		return
	}
	cp.StartsAt = startsAt
	cp.EndsAt = endsAt

	if req.MaxUses >= 0 && req.MaxUses <= 10000000 {
		cp.MaxUses = req.MaxUses
	}
	if req.PerUserLimit != nil && *req.PerUserLimit >= 0 && *req.PerUserLimit <= 100000 {
		cp.PerUserLimit = *req.PerUserLimit
	}
	if req.Active != nil {
		cp.Active = *req.Active
	}
	// Preserve concurrent UsedCount increments via Omit("used_count")
	if err := s.db.Omit("used_count").Save(&cp).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新优惠券失败"})
		return
	}
	_ = s.db.First(&cp, cp.ID).Error
	s.recordAudit(c, "admin.update_coupon", cp.Code, fmt.Sprintf("更新优惠券 %s (active=%v)", cp.Code, cp.Active))
	c.JSON(http.StatusOK, cp)
}

// DELETE /api/v1/admin/coupons/:id
func (s *Server) handleAdminDeleteCoupon(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid coupon id"})
		return
	}
	var cp model.Coupon
	if err := s.db.First(&cp, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "优惠券不存在"})
		return
	}
	s.db.Delete(&model.Coupon{}, id)
	s.recordAudit(c, "admin.delete_coupon", cp.Code, fmt.Sprintf("删除优惠券 %s", cp.Name))
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// ============================================================================
// Affiliate / Referral Commission System
// ============================================================================

func sanitizeAffiliateRate(rate float64) float64 {
	if math.IsNaN(rate) || math.IsInf(rate, 0) || rate <= 0 {
		return 0
	}
	if rate > 50.0 {
		return 50.0
	}
	return math.Round(rate*100) / 100
}

func computeCommissionCents(baseCents int64, ratePercent float64) int64 {
	if baseCents <= 0 {
		return 0
	}
	rate := sanitizeAffiliateRate(ratePercent)
	if rate <= 0 {
		return 0
	}
	comm := int64(math.Round(float64(baseCents) * rate / 100.0))
	if comm < 0 {
		return 0
	}
	if comm > baseCents {
		return baseCents
	}
	return comm
}

// settleAffiliateOnRechargeTx settles inviter commission when an invited user's recharge order is paid,
// and records CommissionedRechargeCents on the invitee so later balance spend will not double-settle commission.
func settleAffiliateOnRechargeTx(tx *gorm.DB, cfg model.SystemConfig, order *model.BillingOrder) error {
	if order == nil || order.ID == 0 || order.AmountCents <= 0 || !cfg.AffiliateEnabled {
		return nil
	}
	rate := sanitizeAffiliateRate(cfg.AffiliateCommissionRate)
	if rate <= 0 {
		return nil
	}

	var invitee model.User
	if err := tx.Select("id, email, invited_by").First(&invitee, order.UserID).Error; err != nil {
		return nil
	}
	if invitee.InvitedBy == 0 || invitee.InvitedBy == invitee.ID {
		return nil
	}

	var inviter model.User
	if err := tx.Select("id, status").First(&inviter, invitee.InvitedBy).Error; err != nil || inviter.Status != "active" {
		return nil
	}

	var existing int64
	tx.Model(&model.AffiliateCommission{}).Where("order_id = ?", order.ID).Count(&existing)
	if existing > 0 {
		return nil
	}

	commCents := computeCommissionCents(order.AmountCents, rate)
	if commCents <= 0 {
		return nil
	}

	rec := model.AffiliateCommission{
		InviterID:       inviter.ID,
		InviteeID:       invitee.ID,
		InviteeEmail:    maskEmail(invitee.Email),
		OrderID:         order.ID,
		OrderNo:         order.OrderNo,
		Scene:           "recharge",
		BaseAmountCents: order.AmountCents,
		RatePercent:     rate,
		CommissionCents: commCents,
	}
	if err := tx.Create(&rec).Error; err != nil {
		return err
	}
	if err := tx.Model(&model.User{}).Where("id = ?", inviter.ID).Updates(map[string]any{
		"commission_balance_cents": gorm.Expr("commission_balance_cents + ?", commCents),
		"total_commission_cents":   gorm.Expr("total_commission_cents + ?", commCents),
	}).Error; err != nil {
		return err
	}
	return tx.Model(&model.User{}).Where("id = ?", invitee.ID).Update(
		"commissioned_recharge_cents", gorm.Expr("commissioned_recharge_cents + ?", order.AmountCents),
	).Error
}

// settleAffiliateOnSpendTx settles inviter commission on plan_purchase / plan_reset for any portion of payableCents
// that was NOT already commissioned at recharge time (preventing double-commission while covering balance/gift spends).
func settleAffiliateOnSpendTx(tx *gorm.DB, cfg model.SystemConfig, order *model.BillingOrder, payableCents int64) error {
	if order == nil || order.ID == 0 || payableCents <= 0 {
		return nil
	}
	var invitee model.User
	if err := tx.Select("id, email, invited_by, commissioned_recharge_cents").First(&invitee, order.UserID).Error; err != nil {
		return nil
	}

	alreadyCovered := invitee.CommissionedRechargeCents
	if alreadyCovered < 0 {
		alreadyCovered = 0
	}
	if alreadyCovered > payableCents {
		alreadyCovered = payableCents
	}
	if alreadyCovered > 0 {
		if err := tx.Model(&model.User{}).Where("id = ?", invitee.ID).Update(
			"commissioned_recharge_cents",
			gorm.Expr("CASE WHEN commissioned_recharge_cents >= ? THEN commissioned_recharge_cents - ? ELSE 0 END", alreadyCovered, alreadyCovered),
		).Error; err != nil {
			return err
		}
	}

	uncommissionedBase := payableCents - alreadyCovered
	if uncommissionedBase <= 0 || !cfg.AffiliateEnabled || invitee.InvitedBy == 0 || invitee.InvitedBy == invitee.ID {
		return nil
	}
	rate := sanitizeAffiliateRate(cfg.AffiliateCommissionRate)
	if rate <= 0 {
		return nil
	}

	var inviter model.User
	if err := tx.Select("id, status").First(&inviter, invitee.InvitedBy).Error; err != nil || inviter.Status != "active" {
		return nil
	}

	var existing int64
	tx.Model(&model.AffiliateCommission{}).Where("order_id = ?", order.ID).Count(&existing)
	if existing > 0 {
		return nil
	}

	commCents := computeCommissionCents(uncommissionedBase, rate)
	if commCents <= 0 {
		return nil
	}

	rec := model.AffiliateCommission{
		InviterID:       inviter.ID,
		InviteeID:       invitee.ID,
		InviteeEmail:    maskEmail(invitee.Email),
		OrderID:         order.ID,
		OrderNo:         order.OrderNo,
		Scene:           order.Type,
		BaseAmountCents: uncommissionedBase,
		RatePercent:     rate,
		CommissionCents: commCents,
	}
	if err := tx.Create(&rec).Error; err != nil {
		return err
	}
	return tx.Model(&model.User{}).Where("id = ?", inviter.ID).Updates(map[string]any{
		"commission_balance_cents": gorm.Expr("commission_balance_cents + ?", commCents),
		"total_commission_cents":   gorm.Expr("total_commission_cents + ?", commCents),
	}).Error
}

func newWithdrawNo() string {
	return "WD" + time.Now().UTC().Format("20060102150405") + strings.ToUpper(utils.GenerateRandomToken(3))
}

// GET /api/v1/affiliate/overview
func (s *Server) handleAffiliateOverview(c *gin.Context) {
	uid := s.currentUserID(c)
	var u model.User
	if err := s.db.First(&u, uid).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	if strings.TrimSpace(u.InviteCode) == "" {
		u.InviteCode = model.GenerateInviteCode()
		s.db.Model(&model.User{}).Where("id = ?", u.ID).Update("invite_code", u.InviteCode)
	}

	cfg := s.getSystemConfig()
	var invitedCount int64
	s.db.Model(&model.User{}).Where("invited_by = ?", uid).Count(&invitedCount)

	var pendingWithdrawCents int64
	s.db.Model(&model.AffiliateWithdrawal{}).
		Select("COALESCE(SUM(amount_cents), 0)").
		Where("user_id = ? AND status = ?", uid, "pending").
		Scan(&pendingWithdrawCents)

	var commissions []model.AffiliateCommission
	s.db.Where("inviter_id = ?", uid).Order("id desc").Limit(100).Find(&commissions)

	var withdrawals []model.AffiliateWithdrawal
	s.db.Where("user_id = ?", uid).Order("id desc").Limit(100).Find(&withdrawals)

	inviteURL := fmt.Sprintf("%s/?ref=%s", s.panelBaseURL(c), url.QueryEscape(u.InviteCode))
	minWithdraw := cfg.AffiliateMinWithdrawCents
	if minWithdraw <= 0 {
		minWithdraw = 1000
	}

	c.JSON(http.StatusOK, gin.H{
		"enabled":                  cfg.AffiliateEnabled,
		"commission_rate":          sanitizeAffiliateRate(cfg.AffiliateCommissionRate),
		"min_withdraw_cents":       minWithdraw,
		"invite_code":              u.InviteCode,
		"invite_url":               inviteURL,
		"invited_count":            invitedCount,
		"commission_balance_cents": u.CommissionBalanceCents,
		"total_commission_cents":   u.TotalCommissionCents,
		"pending_withdraw_cents":   pendingWithdrawCents,
		"commissions":              commissions,
		"withdrawals":              withdrawals,
	})
}

// POST /api/v1/affiliate/transfer
func (s *Server) handleAffiliateTransfer(c *gin.Context) {
	uid := s.currentUserID(c)
	var req struct {
		AmountCents int64 `json:"amount_cents"` // <= 0 transfers full available commission balance
	}
	if c.Request != nil && c.Request.Body != nil && c.Request.Body != http.NoBody {
		raw, err := io.ReadAll(c.Request.Body)
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "请求体超过大小限制"})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": "读取请求参数失败"})
			return
		}
		if strings.TrimSpace(string(raw)) != "" {
			if err := json.Unmarshal(raw, &req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的划转参数"})
				return
			}
		}
	}

	var updatedUser model.User
	var transferred int64
	now := time.Now()

	txErr := s.db.Transaction(func(tx *gorm.DB) error {
		var u model.User
		if err := tx.First(&u, uid).Error; err != nil {
			return fmt.Errorf("not_found")
		}
		amount := req.AmountCents
		if amount <= 0 {
			amount = u.CommissionBalanceCents
		}
		if amount <= 0 {
			return fmt.Errorf("empty_commission")
		}
		if amount > maxWithdrawAmountCent {
			return fmt.Errorf("exceeds_limit")
		}
		res := tx.Model(&model.User{}).
			Where("id = ? AND commission_balance_cents >= ?", uid, amount).
			Updates(map[string]any{
				"commission_balance_cents":    gorm.Expr("commission_balance_cents - ?", amount),
				"balance_cents":               gorm.Expr("balance_cents + ?", amount),
				"commissioned_recharge_cents": gorm.Expr("commissioned_recharge_cents + ?", amount),
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("insufficient_commission")
		}
		transferred = amount
		if err := tx.First(&updatedUser, uid).Error; err != nil {
			return err
		}
		order := model.BillingOrder{
			OrderNo:       newOrderNo(),
			UserID:        uid,
			UserEmail:     updatedUser.Email,
			Type:          "affiliate_transfer",
			PlanName:      "推广佣金划转至账户余额",
			OriginalCents: amount,
			AmountCents:   amount,
			Status:        "paid",
			Gateway:       "affiliate",
			PaidAt:        &now,
		}
		return tx.Create(&order).Error
	})
	if txErr != nil {
		switch txErr.Error() {
		case "empty_commission", "insufficient_commission":
			c.JSON(http.StatusBadRequest, gin.H{"error": "当前可划转返利佣金不足"})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "佣金划转失败，请稍后再试"})
		}
		return
	}
	s.recordAuditForUser(c, updatedUser.ID, updatedUser.Email, "affiliate.transfer", updatedUser.Email,
		fmt.Sprintf("佣金一键划转余额 ¥%.2f", float64(transferred)/100.0))
	c.JSON(http.StatusOK, gin.H{
		"message":           fmt.Sprintf("已将 ¥%.2f 推广佣金实时划转至账户余额", float64(transferred)/100.0),
		"transferred_cents": transferred,
		"user":              updatedUser,
	})
}

// POST /api/v1/affiliate/withdraw
func (s *Server) handleAffiliateWithdraw(c *gin.Context) {
	uid := s.currentUserID(c)
	var req struct {
		AmountCents int64  `json:"amount_cents" binding:"required"`
		Method      string `json:"method" binding:"required"`
		Account     string `json:"account" binding:"required"`
		RealName    string `json:"real_name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请完整填写提现金额、收款方式与收款账号"})
		return
	}
	method := strings.ToLower(strings.TrimSpace(req.Method))
	if method != "usdt" && method != "alipay" && method != "wechat" && method != "bank" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "收款方式需为 usdt / alipay / wechat / bank"})
		return
	}
	account := sanitizeSingleLine(req.Account, 190)
	if len(account) < 3 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请输入有效的收款地址或收款账号"})
		return
	}
	realName := sanitizeSingleLine(req.RealName, 64)

	cfg := s.getSystemConfig()
	minWithdraw := cfg.AffiliateMinWithdrawCents
	if minWithdraw <= 0 {
		minWithdraw = 1000
	}
	if req.AmountCents < minWithdraw {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("单笔最低提现金额为 ¥%.2f", float64(minWithdraw)/100.0)})
		return
	}
	if req.AmountCents > maxWithdrawAmountCent {
		c.JSON(http.StatusBadRequest, gin.H{"error": "提现金额超出单笔上限"})
		return
	}

	var withdrawal model.AffiliateWithdrawal
	var updatedUser model.User

	txErr := s.db.Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&model.User{}).
			Where("id = ? AND commission_balance_cents >= ?", uid, req.AmountCents).
			Update("commission_balance_cents", gorm.Expr("commission_balance_cents - ?", req.AmountCents))
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("insufficient_commission")
		}
		if err := tx.First(&updatedUser, uid).Error; err != nil {
			return err
		}
		withdrawal = model.AffiliateWithdrawal{
			WithdrawNo:  newWithdrawNo(),
			UserID:      uid,
			UserEmail:   updatedUser.Email,
			AmountCents: req.AmountCents,
			Method:      method,
			Account:     account,
			RealName:    realName,
			Status:      "pending",
		}
		return tx.Create(&withdrawal).Error
	})
	if txErr != nil {
		if txErr.Error() == "insufficient_commission" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "可提现佣金余额不足"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "提交提现申请失败，请稍后重试"})
		return
	}

	s.recordAuditForUser(c, updatedUser.ID, updatedUser.Email, "affiliate.withdraw_request", withdrawal.WithdrawNo,
		fmt.Sprintf("提交佣金提现申请 ¥%.2f (%s)", float64(withdrawal.AmountCents)/100.0, withdrawal.Method))
	c.JSON(http.StatusCreated, gin.H{
		"message":    "提现申请已提交，等待管理员审核打款",
		"withdrawal": withdrawal,
		"user":       updatedUser,
	})
}

// GET /api/v1/admin/affiliate/withdrawals
func (s *Server) handleAdminListWithdrawals(c *gin.Context) {
	query := s.db.Model(&model.AffiliateWithdrawal{})
	if st := strings.TrimSpace(c.Query("status")); st != "" && st != "all" {
		query = query.Where("status = ?", st)
	}
	if q := strings.TrimSpace(c.Query("q")); q != "" {
		like := buildSafeLike(q)
		query = query.Where(`(withdraw_no LIKE ? ESCAPE '!' OR user_email LIKE ? ESCAPE '!' OR account LIKE ? ESCAPE '!')`, like, like, like)
	}
	var total int64
	query.Count(&total)
	page, pageSize, pagedEnvelope := parseListPagination(c, 200, 500)
	var list []model.AffiliateWithdrawal
	query.Order("CASE WHEN status = 'pending' THEN 0 ELSE 1 END asc, id desc").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&list)
	respondListPayload(c, list, total, page, pageSize, pagedEnvelope)
}

// POST /api/v1/admin/affiliate/withdrawals/:id/review
func (s *Server) handleAdminReviewWithdrawal(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid withdrawal id"})
		return
	}
	var req struct {
		Action string `json:"action" binding:"required"` // "approve" | "reject"
		Remark string `json:"remark"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请指定审核动作 (approve / reject)"})
		return
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action != "approve" && action != "reject" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "审核动作必须为 approve 或 reject"})
		return
	}
	remark := sanitizeSingleLine(req.Remark, 255)
	reviewerID := s.currentUserID(c)
	now := time.Now()

	var updated model.AffiliateWithdrawal
	txErr := s.db.Transaction(func(tx *gorm.DB) error {
		var wd model.AffiliateWithdrawal
		if err := tx.First(&wd, id).Error; err != nil {
			return fmt.Errorf("not_found")
		}
		if wd.Status != "pending" {
			return fmt.Errorf("already_reviewed")
		}
		targetStatus := "approved"
		if action == "reject" {
			targetStatus = "rejected"
		}
		res := tx.Model(&model.AffiliateWithdrawal{}).
			Where("id = ? AND status = ?", wd.ID, "pending").
			Updates(map[string]any{
				"status":       targetStatus,
				"admin_remark": remark,
				"reviewed_by":  reviewerID,
				"reviewed_at":  &now,
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("already_reviewed")
		}
		if targetStatus == "rejected" {
			if err := tx.Model(&model.User{}).
				Where("id = ?", wd.UserID).
				Update("commission_balance_cents", gorm.Expr("commission_balance_cents + ?", wd.AmountCents)).Error; err != nil {
				return err
			}
		}
		return tx.First(&updated, wd.ID).Error
	})
	if txErr != nil {
		switch txErr.Error() {
		case "not_found":
			c.JSON(http.StatusNotFound, gin.H{"error": "提现工单不存在"})
		case "already_reviewed":
			c.JSON(http.StatusConflict, gin.H{"error": "该提现申请已审核处理，请勿重复操作"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "审核处理失败"})
		}
		return
	}

	s.recordAudit(c, "admin.review_withdrawal", updated.WithdrawNo,
		fmt.Sprintf("审核提现申请 %s: %s (¥%.2f)", updated.WithdrawNo, updated.Status, float64(updated.AmountCents)/100.0))
	c.JSON(http.StatusOK, gin.H{
		"message":    "提现申请审核结果已保存",
		"withdrawal": updated,
	})
}

// ============================================================================
// Ticket Customer Support Center & Webhook / Telegram Push Integration
// ============================================================================

func normalizeTicketCategory(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "network", "rule", "billing", "account", "general":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return "general"
	}
}

func normalizeTicketPriority(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "low", "normal", "high", "urgent":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return "normal"
	}
}

func ticketCategoryLabel(cat string) string {
	switch cat {
	case "network":
		return "线路与网络"
	case "rule":
		return "转发规则"
	case "billing":
		return "账单与支付"
	case "account":
		return "账号与权限"
	default:
		return "综合咨询"
	}
}

func newTicketNo() string {
	return "TK" + time.Now().UTC().Format("20060102150405") + strings.ToUpper(utils.GenerateRandomToken(3))
}

// GET /api/v1/tickets
func (s *Server) handleListTickets(c *gin.Context) {
	uid := s.currentUserID(c)
	query := s.db.Model(&model.SupportTicket{}).Where("user_id = ?", uid)
	if st := strings.TrimSpace(c.Query("status")); st != "" && st != "all" {
		query = query.Where("status = ?", st)
	}
	if cat := strings.TrimSpace(c.Query("category")); cat != "" && cat != "all" {
		query = query.Where("category = ?", cat)
	}
	if q := strings.TrimSpace(c.Query("q")); q != "" {
		like := buildSafeLike(q)
		query = query.Where(`(ticket_no LIKE ? ESCAPE '!' OR subject LIKE ? ESCAPE '!' OR rule_name LIKE ? ESCAPE '!')`, like, like, like)
	}
	var total int64
	query.Count(&total)
	page, pageSize, pagedEnvelope := parseListPagination(c, 100, 300)
	var tickets []model.SupportTicket
	query.Order("CASE WHEN status = 'closed' THEN 1 ELSE 0 END asc, last_message_at desc, id desc").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&tickets)
	respondListPayload(c, tickets, total, page, pageSize, pagedEnvelope)
}

// GET /api/v1/admin/tickets
func (s *Server) handleAdminListTickets(c *gin.Context) {
	query := s.db.Model(&model.SupportTicket{})
	if st := strings.TrimSpace(c.Query("status")); st != "" && st != "all" {
		query = query.Where("status = ?", st)
	}
	if cat := strings.TrimSpace(c.Query("category")); cat != "" && cat != "all" {
		query = query.Where("category = ?", cat)
	}
	if prio := strings.TrimSpace(c.Query("priority")); prio != "" && prio != "all" {
		query = query.Where("priority = ?", prio)
	}
	if q := strings.TrimSpace(c.Query("q")); q != "" {
		like := buildSafeLike(q)
		query = query.Where(`(ticket_no LIKE ? ESCAPE '!' OR subject LIKE ? ESCAPE '!' OR user_email LIKE ? ESCAPE '!' OR rule_name LIKE ? ESCAPE '!')`, like, like, like, like)
	}
	var total int64
	query.Count(&total)
	page, pageSize, pagedEnvelope := parseListPagination(c, 200, 500)
	var tickets []model.SupportTicket
	query.Order("CASE WHEN status IN ('open', 'customer_reply') THEN 0 WHEN status = 'answered' THEN 1 ELSE 2 END asc, last_message_at desc, id desc").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&tickets)
	respondListPayload(c, tickets, total, page, pageSize, pagedEnvelope)
}

// POST /api/v1/tickets
func (s *Server) handleCreateTicket(c *gin.Context) {
	uid := s.currentUserID(c)
	var req struct {
		Subject  string `json:"subject" binding:"required"`
		Category string `json:"category"`
		Priority string `json:"priority"`
		RuleID   uint64 `json:"rule_id"`
		Message  string `json:"message" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请填写工单标题与问题描述"})
		return
	}
	subject := sanitizeSingleLine(req.Subject, 160)
	message := sanitizeCleanText(req.Message, 4000)
	if utf8.RuneCountInString(subject) < 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "工单标题至少需要 2 个字符"})
		return
	}
	if utf8.RuneCountInString(message) < 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "工单内容至少需要 2 个字符"})
		return
	}

	var u model.User
	if err := s.db.First(&u, uid).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}

	var ruleID uint64
	var ruleName string
	if req.RuleID > 0 {
		var rule model.ForwardRule
		if err := s.db.First(&rule, req.RuleID).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "关联的转发规则不存在"})
			return
		}
		if rule.UserID != uid && !s.isAdmin(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "禁止关联非本人名下的转发规则"})
			return
		}
		ruleID = rule.ID
		ruleName = truncateUTF8(fmt.Sprintf("#%d %s (:%d)", rule.ID, rule.Name, rule.ListenPort), 160)
	}

	now := time.Now()
	cat := normalizeTicketCategory(req.Category)
	prio := normalizeTicketPriority(req.Priority)
	senderRole := "user"
	if s.isAdmin(c) {
		senderRole = "admin"
	}

	var createdTicket model.SupportTicket
	var firstMsg model.TicketMessage
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if u.Role != "admin" {
			var openCount int64
			tx.Model(&model.SupportTicket{}).
				Where("user_id = ? AND status <> ?", uid, "closed").
				Count(&openCount)
			if openCount >= maxOpenTicketsPerUser {
				return fmt.Errorf("too_many_open_tickets")
			}
		}
		createdTicket = model.SupportTicket{
			TicketNo:      newTicketNo(),
			UserID:        uid,
			UserEmail:     u.Email,
			Subject:       subject,
			Category:      cat,
			Priority:      prio,
			RuleID:        ruleID,
			RuleName:      ruleName,
			Status:        "open",
			LastReplyBy:   senderRole,
			LastMessageAt: now,
		}
		if err := tx.Create(&createdTicket).Error; err != nil {
			return err
		}
		firstMsg = model.TicketMessage{
			TicketID:    createdTicket.ID,
			SenderID:    uid,
			SenderEmail: u.Email,
			SenderRole:  senderRole,
			Content:     message,
			CreatedAt:   now,
		}
		return tx.Create(&firstMsg).Error
	})
	if err != nil {
		if err.Error() == "too_many_open_tickets" {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "您当前未结单的工单数量已达上限，请先在现有工单中补充说明或关闭已解决工单"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建工单失败，请稍后重试"})
		return
	}

	s.recordAuditForUser(c, u.ID, u.Email, "ticket.create", createdTicket.TicketNo,
		fmt.Sprintf("提交客服工单 [%s] %s", ticketCategoryLabel(cat), createdTicket.Subject))

	if s.orch != nil && s.orch.Notifier() != nil {
		ruleLine := ""
		if ruleName != "" {
			ruleLine = fmt.Sprintf("\n关联规则：%s", ruleName)
		}
		s.orch.Notifier().NotifyTicketEventAsync(
			"ticket_created",
			fmt.Sprintf("新工单提醒 %s", createdTicket.TicketNo),
			fmt.Sprintf("用户：%s\n分类：%s (%s)%s\n标题：%s\n内容：%s",
				u.Email, ticketCategoryLabel(cat), strings.ToUpper(prio), ruleLine,
				createdTicket.Subject, truncateUTF8(message, 240)),
		)
	}

	c.JSON(http.StatusCreated, gin.H{
		"ticket":   createdTicket,
		"messages": []model.TicketMessage{firstMsg},
	})
}

// GET /api/v1/tickets/:id
func (s *Server) handleGetTicketDetail(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ticket id"})
		return
	}
	var ticket model.SupportTicket
	if err := s.db.First(&ticket, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "工单不存在"})
		return
	}
	uid := s.currentUserID(c)
	if ticket.UserID != uid && !s.isAdmin(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权查看他人工单"})
		return
	}
	var messages []model.TicketMessage
	s.db.Where("ticket_id = ?", ticket.ID).Order("id asc").Find(&messages)
	c.JSON(http.StatusOK, gin.H{
		"ticket":   ticket,
		"messages": messages,
	})
}

// POST /api/v1/tickets/:id/reply
func (s *Server) handleReplyTicket(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ticket id"})
		return
	}
	var req struct {
		Message string `json:"message" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请输入回复内容"})
		return
	}
	content := sanitizeCleanText(req.Message, 4000)
	if utf8.RuneCountInString(content) < 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "回复内容不能为空"})
		return
	}

	uid := s.currentUserID(c)
	isAdmin := s.isAdmin(c)

	var sender model.User
	if err := s.db.Select("id, email, role").First(&sender, uid).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户不存在"})
		return
	}

	var ticket model.SupportTicket
	if err := s.db.First(&ticket, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "工单不存在"})
		return
	}
	if ticket.UserID != uid && !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权回复他人工单"})
		return
	}
	if ticket.Status == "closed" && !isAdmin {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该工单已结单关闭，如需继续咨询请提交新工单"})
		return
	}

	now := time.Now()
	senderRole := "user"
	nextStatus := "customer_reply"
	if isAdmin {
		senderRole = "admin"
		nextStatus = "answered"
	}

	var msg model.TicketMessage
	err = s.db.Transaction(func(tx *gorm.DB) error {
		updates := map[string]any{
			"status":          nextStatus,
			"last_reply_by":   senderRole,
			"last_message_at": now,
			"closed_at":       nil,
		}
		query := tx.Model(&model.SupportTicket{}).Where("id = ?", ticket.ID)
		if !isAdmin {
			query = query.Where("status <> ?", "closed")
		}
		res := query.Updates(updates)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("ticket_closed")
		}
		msg = model.TicketMessage{
			TicketID:    ticket.ID,
			SenderID:    uid,
			SenderEmail: sender.Email,
			SenderRole:  senderRole,
			Content:     content,
			CreatedAt:   now,
		}
		return tx.Create(&msg).Error
	})
	if err != nil {
		if err.Error() == "ticket_closed" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "该工单已结单关闭，如需继续咨询请提交新工单"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "发送工单回复失败"})
		return
	}
	_ = s.db.First(&ticket, ticket.ID).Error

	if s.orch != nil && s.orch.Notifier() != nil {
		actorLabel := "用户追问"
		if senderRole == "admin" {
			actorLabel = "客服回复"
		}
		s.orch.Notifier().NotifyTicketEventAsync(
			"ticket_replied",
			fmt.Sprintf("工单%s %s", actorLabel, ticket.TicketNo),
			fmt.Sprintf("工单：%s (%s)\n回复人：%s (%s)\n内容：%s",
				ticket.Subject, ticket.TicketNo, sender.Email, actorLabel, truncateUTF8(content, 240)),
		)
	}

	c.JSON(http.StatusOK, gin.H{
		"ticket":  ticket,
		"message": msg,
	})
}

// POST /api/v1/tickets/:id/close
func (s *Server) handleCloseTicket(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ticket id"})
		return
	}
	var ticket model.SupportTicket
	if err := s.db.First(&ticket, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "工单不存在"})
		return
	}
	uid := s.currentUserID(c)
	if ticket.UserID != uid && !s.isAdmin(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权操作他人工单"})
		return
	}
	now := time.Now()
	s.db.Model(&model.SupportTicket{}).Where("id = ?", ticket.ID).Updates(map[string]any{
		"status":    "closed",
		"closed_at": &now,
	})
	_ = s.db.First(&ticket, ticket.ID).Error
	s.recordAudit(c, "ticket.close", ticket.TicketNo, fmt.Sprintf("关闭工单 %s", ticket.Subject))
	c.JSON(http.StatusOK, gin.H{
		"message": "工单已关闭",
		"ticket":  ticket,
	})
}

// POST /api/v1/admin/tickets/:id/status
func (s *Server) handleAdminUpdateTicketStatus(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ticket id"})
		return
	}
	var req struct {
		Status   string `json:"status" binding:"required"`
		Priority string `json:"priority"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请指定目标工单状态"})
		return
	}
	st := strings.ToLower(strings.TrimSpace(req.Status))
	if st != "open" && st != "answered" && st != "customer_reply" && st != "closed" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的工单状态"})
		return
	}
	var ticket model.SupportTicket
	if err := s.db.First(&ticket, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "工单不存在"})
		return
	}
	now := time.Now()
	updates := map[string]any{"status": st}
	if st == "closed" {
		updates["closed_at"] = &now
	} else {
		updates["closed_at"] = nil
	}
	if strings.TrimSpace(req.Priority) != "" {
		updates["priority"] = normalizeTicketPriority(req.Priority)
	}
	s.db.Model(&model.SupportTicket{}).Where("id = ?", ticket.ID).Updates(updates)
	_ = s.db.First(&ticket, ticket.ID).Error
	s.recordAudit(c, "admin.ticket_status", ticket.TicketNo, fmt.Sprintf("变更工单 %s 状态为 %s", ticket.TicketNo, st))
	c.JSON(http.StatusOK, gin.H{
		"message": "工单状态已更新",
		"ticket":  ticket,
	})
}
