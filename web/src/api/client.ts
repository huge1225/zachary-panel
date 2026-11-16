export type EngineType = 'native' | 'gost' | 'realm' | 'nftables'

export interface TargetEndpoint {
  address: string
  weight?: number
  backup?: boolean
}

export interface SystemConfig {
  id?: number
  site_name: string
  site_logo: string
  announcement: string
  allow_register: boolean
  default_role_group_id?: number
  default_plan_id?: number
  default_quota_gb?: number
  default_max_rules?: number
  default_speed_mbps?: number
  default_tunnels?: string
  payment_enabled?: boolean
  epay_enabled?: boolean
  epay_url?: string
  epay_pid?: string
  epay_key?: string
  usdt_address?: string
  recharge_notice?: string
  notify_telegram_bot_token?: string
  notify_telegram_chat_id?: string
  notify_webhook_url?: string
  notify_on_node_events?: boolean
  notify_on_quota_events?: boolean
  admin_api_key_prefix?: string
}

export interface RoleGroup {
  id: number
  name: string
  description: string
  allowed_tunnels: string
}

export interface User {
  id: number
  email: string
  role: 'admin' | 'user'
  status: string
  role_group_id?: number
  plan_id: number
  allowed_tunnels?: string
  balance_cents: number
  quota_bytes: number
  used_bytes: number
  max_rules: number
  speed_mbps: number
  expire_at: string
  monthly_reset?: boolean
  last_reset_at?: string
  sub_token?: string
  totp_enabled?: boolean
}

export interface NodeItem {
  id: number
  name: string
  group_id: number
  role: 'relay' | 'ingress' | 'egress' | 'all'
  server_ip: string
  connect_ip: string
  public_host: string
  internal_host?: string
  port_range: string
  traffic_rate: number
  quota_bytes: number
  used_bytes: number
  reset_day?: number
  last_reset_month?: string
  default_engine: EngineType
  supported_engines: string
  agent_version?: string
  secret_token?: string
  status: 'online' | 'offline' | 'maintenance'
  cpu_cores: number
  cpu_usage: number
  load_1: number
  load_5: number
  load_15: number
  mem_used_bytes: number
  mem_total_bytes: number
  mem_usage: number
  disk_used_bytes: number
  disk_total_bytes: number
  disk_usage: number
  net_in_delta: number
  net_out_delta: number
  active_rules: number
  active_conns: number
  uptime_seconds: number
}

export interface TunnelLine {
  id: number
  name: string
  type: 'direct' | 'encrypt'
  description: string
  ingress_node_id: number
  egress_node_id: number
  transport: 'raw' | 'tls' | 'ws' | 'wss' | 'quic' | 'custom'
  engine: EngineType
  billing_mode: 'one_way' | 'two_way'
  rate_multiplier: number
  max_port_count: number
  port_range: string
  enabled: boolean
}

export interface ForwardRule {
  id: number
  user_id: number
  name: string
  mode: 'direct' | 'tunnel'
  ingress_node_id: number
  tunnel_line_id: number
  engine: EngineType
  effective_engine?: EngineType // 实际运行的引擎（限速规则会从 gost/realm 回退到 native）
  protocol: 'tcp' | 'udp' | 'both'
  listen_port: number
  relay_port: number
  load_balance: 'round_robin' | 'failover'
  targets_json: string
  speed_mbps: number
  access_mode?: 'off' | 'allow' | 'deny'
  access_cidrs?: string
  upload_bytes: number
  down_bytes: number
  billed_bytes: number
  enabled: boolean
  status: string
  last_error?: string
}

export interface Plan {
  id: number
  name: string
  description: string
  role_group_id: number
  price_cents: number
  duration_days: number
  quota_bytes: number
  max_rules: number
  speed_mbps: number
  monthly_reset?: boolean
  allowed_tunnels?: string
  active?: boolean
}

export interface RedeemCodeItem {
  id: number
  code: string
  plan_id: number
  plan_name?: string
  balance_cents: number
  quota_bytes: number
  duration_days: number
  note: string
  used_by: number
  used_by_email?: string
  used_at?: string
  created_at: string
}

const API_BASE = '/api/v1'

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem('nexus_token')
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  })
  const renewedToken = res.headers.get('X-Renewed-Token')
  if (renewedToken) {
    localStorage.setItem('nexus_token', renewedToken)
  }
  const data = await res.json().catch(() => ({}))
  if (res.status === 401 && token && !path.startsWith('/auth/')) {
    // Token expired or revoked (e.g. password changed elsewhere): drop it and return to the login page.
    localStorage.removeItem('nexus_token')
    window.dispatchEvent(new CustomEvent('nexus-unauthorized'))
  }
  if (!res.ok) {
    const err = new Error(data.error || `HTTP ${res.status}`) as Error & { totp_required?: boolean }
    if (data.totp_required) {
      err.totp_required = true
    }
    throw err
  }
  return data as T
}

export const api = {
  getSiteConfig: () => request<SystemConfig>('/site-config'),

  login: (email: string, password: string, totpCode?: string) =>
    request<{ token: string; user: User }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password, totp_code: totpCode || '' }),
    }),

  setupTOTP: () =>
    request<{ secret: string; otpauth_url: string }>('/user/totp/setup', {
      method: 'POST',
    }),

  enableTOTP: (code: string) =>
    request<{ message: string; totp_enabled: boolean }>('/user/totp/enable', {
      method: 'POST',
      body: JSON.stringify({ code }),
    }),

  disableTOTP: (payload: { password?: string; code?: string }) =>
    request<{ message: string; totp_enabled: boolean }>('/user/totp/disable', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  adminGenerateAPIKey: () =>
    request<{ api_key: string; admin_api_key_prefix: string; message: string }>('/admin/settings/api-key', {
      method: 'POST',
    }),

  adminRevokeAPIKey: () =>
    request<{ message: string }>('/admin/settings/api-key', {
      method: 'DELETE',
    }),

  changePassword: (oldPassword: string, newPassword: string) =>
    request<{ message: string; token: string }>('/user/password', {
      method: 'POST',
      body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
    }),

  resetSubToken: () =>
    request<{ message: string; sub_token: string }>('/user/reset-sub-token', {
      method: 'POST',
    }),

  resetSubscription: () =>
    request<{ message: string; user: User }>('/user/reset-subscription', {
      method: 'POST',
    }),

  register: (email: string, password: string) =>
    request<{ token: string; user: User }>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    }),

  getDashboard: () =>
    request<{
      user: User
      total_rules: number
      running_rules: number
      total_nodes: number
      online_nodes: number
      hourly_stats: Array<{
        hour_bucket: string
        upload_bytes: number
        down_bytes: number
        billed_bytes: number
      }>
      global_hourly_stats?: Array<{
        hour_bucket: string
        upload_bytes: number
        down_bytes: number
        billed_bytes: number
      }>
      top_users?: Array<{
        id: number
        email: string
        used_bytes: number
        quota_bytes: number
        plan_id: number
      }>
      top_nodes?: Array<{
        id: number
        name: string
        used_bytes: number
        quota_bytes: number
        status: string
      }>
      engines: Array<{ id: EngineType; name: string; desc: string }>
    }>('/dashboard'),

  getNodes: () => request<NodeItem[]>('/nodes'),
  getLines: () => request<TunnelLine[]>('/lines'),
  getRules: () => request<ForwardRule[]>('/rules'),
  getTelemetry: () =>
    request<{
      timestamp: number
      user: {
        id: number
        role_group_id?: number
        plan_id?: number
        balance_cents?: number
        quota_bytes: number
        used_bytes: number
        max_rules?: number
        speed_mbps?: number
        expire_at?: string
        status: string
        allowed_tunnels?: string
      }
      nodes: Partial<NodeItem>[]
      rules: Array<{
        id: number
        upload_bytes: number
        down_bytes: number
        billed_bytes: number
        enabled: boolean
        status: string
      }>
    }>('/telemetry'),

  createRule: (payload: {
    name: string
    mode: 'direct' | 'tunnel'
    ingress_node_id: number
    tunnel_line_id: number
    engine: EngineType
    protocol: 'tcp' | 'udp' | 'both'
    listen_port: number
    load_balance: 'round_robin' | 'failover'
    targets: TargetEndpoint[]
    speed_mbps: number
    access_mode?: 'off' | 'allow' | 'deny'
    access_cidrs?: string
  }) =>
    request<ForwardRule>('/rules', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  batchCreateRules: (payload: {
    tunnel_line_id: number
    protocol: 'tcp' | 'udp' | 'both'
    items: Array<{
      name: string
      listen_port: number
      port_range?: string
      targets: TargetEndpoint[]
      protocol?: 'tcp' | 'udp' | 'both'
      load_balance?: 'round_robin' | 'failover'
    }>
  }) =>
    request<ForwardRule[]>('/rules/batch', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  updateRule: (id: number, payload: unknown) =>
    request<ForwardRule>(`/rules/${id}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),

  toggleRule: (id: number) =>
    request<ForwardRule>(`/rules/${id}/toggle`, { method: 'POST' }),

  probeRule: (id: number) =>
    request<{ tunnel_ms?: number; latencies: Record<string, number> }>(`/rules/${id}/probe`, {
      method: 'POST',
    }),

  deleteRule: (id: number) =>
    request<{ deleted: boolean }>(`/rules/${id}`, { method: 'DELETE' }),

  batchDeleteRules: (ids: number[]) =>
    request<{ deleted: number; ids: number[] }>('/rules/batch-delete', {
      method: 'POST',
      body: JSON.stringify({ ids }),
    }),

  getRoles: () => request<RoleGroup[]>('/roles'),
  getPlans: () => request<Plan[]>('/plans'),
  purchasePlan: (id: number) =>
    request<{ message: string; user: User }>(`/plans/${id}/purchase`, {
      method: 'POST',
    }),
  redeemCode: (code: string) =>
    request<{ message: string; user: User }>('/redeem', {
      method: 'POST',
      body: JSON.stringify({ code }),
    }),

  // Admin APIs
  adminCreateRole: (payload: Partial<RoleGroup>) =>
    request<RoleGroup>('/admin/roles', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  adminUpdateRole: (id: number, payload: Partial<RoleGroup>) =>
    request<RoleGroup>(`/admin/roles/${id}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  adminDeleteRole: (id: number) =>
    request<{ deleted: boolean }>(`/admin/roles/${id}`, { method: 'DELETE' }),

  adminCreatePlan: (payload: Partial<Plan>) =>
    request<Plan>('/admin/plans', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  adminUpdatePlan: (id: number, payload: Partial<Plan>) =>
    request<Plan>(`/admin/plans/${id}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  adminDeletePlan: (id: number) =>
    request<{ deleted: boolean }>(`/admin/plans/${id}`, { method: 'DELETE' }),

  adminCreateNode: (node: Partial<NodeItem>) =>
    request<NodeItem>('/admin/nodes', {
      method: 'POST',
      body: JSON.stringify(node),
    }),
  adminUpdateNode: (id: number, node: Partial<NodeItem>) =>
    request<NodeItem>(`/admin/nodes/${id}`, {
      method: 'PUT',
      body: JSON.stringify(node),
    }),
  adminDeleteNode: (id: number) =>
    request<{ deleted: boolean }>(`/admin/nodes/${id}`, { method: 'DELETE' }),
  adminGetNodeInstallCmd: (id: number) =>
    request<{
      node_id: number
      install_cmd: string
      systemd_install: string
      systemd_uninstall: string
      docker_install: string
      docker_uninstall: string
      direct_run?: string
      warnings?: string[]
      sync_policy: {
        heartbeat_traffic_sec: number
        rule_dispatch: string
        full_reconcile_sec: number
        restart_recovery: string
      }
    }>(`/admin/nodes/${id}/install-cmd`),
  adminResyncNode: (id: number) =>
    request<{ status: string; node_id: number }>(`/admin/nodes/${id}/resync`, {
      method: 'POST',
    }),
  adminResetNodeTraffic: (id: number) =>
    request<{ node: NodeItem; resumed_rules: number }>(`/admin/nodes/${id}/reset-traffic`, {
      method: 'POST',
    }),
  adminUpgradeNode: (id: number, target_version?: string) =>
    request<{ message: string; node_id: number; target_version: string }>(`/admin/nodes/${id}/upgrade`, {
      method: 'POST',
      body: JSON.stringify({ target_version: target_version || '' }),
    }),
  adminBatchUpgradeNodes: (ids?: number[], target_version?: string) =>
    request<{ message: string; upgraded_nodes: number[]; target_version: string }>('/admin/nodes/batch-upgrade', {
      method: 'POST',
      body: JSON.stringify({ ids: ids || [], target_version: target_version || '' }),
    }),
  adminCreateLine: (line: Partial<TunnelLine>) =>
    request<TunnelLine>('/admin/lines', {
      method: 'POST',
      body: JSON.stringify(line),
    }),
  adminUpdateLine: (id: number, line: Partial<TunnelLine>) =>
    request<TunnelLine>(`/admin/lines/${id}`, {
      method: 'PUT',
      body: JSON.stringify(line),
    }),
  adminDeleteLine: (id: number) =>
    request<{ deleted: boolean }>(`/admin/lines/${id}`, { method: 'DELETE' }),
  adminListUsers: () => request<User[]>('/admin/users'),
  adminCreateUser: (payload: Partial<User> & { password?: string }) =>
    request<User>('/admin/users', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  adminUpdateUser: (id: number, payload: Partial<User> & { password?: string }) =>
    request<User>(`/admin/users/${id}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  adminDeleteUser: (id: number) =>
    request<{ deleted: boolean }>(`/admin/users/${id}`, { method: 'DELETE' }),
  adminResetUserTraffic: (id: number) =>
    request<User>(`/admin/users/${id}/reset-traffic`, { method: 'POST' }),
  adminResetUserSubscription: (
    id: number,
    payload?: { duration_days?: number; reset_sub_token?: boolean },
  ) =>
    request<User>(`/admin/users/${id}/reset-subscription`, {
      method: 'POST',
      body: JSON.stringify(payload || {}),
    }),
  adminResetUserPassword: (id: number, password?: string) =>
    request<{
      message: string
      password: string
      generated: boolean
      user: User
      token?: string
    }>(`/admin/users/${id}/reset-password`, {
      method: 'POST',
      body: JSON.stringify({ password: password || '' }),
    }),
  adminResetUserSubToken: (id: number) =>
    request<{ message: string; sub_token: string; user: User }>(
      `/admin/users/${id}/reset-sub-token`,
      { method: 'POST' },
    ),
  adminGetSettings: () => request<SystemConfig>('/admin/settings'),
  adminUpdateSettings: (payload: Partial<SystemConfig>) =>
    request<SystemConfig>('/admin/settings', {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  adminTestNotify: () =>
    request<{ message: string }>('/admin/settings/test-notify', {
      method: 'POST',
    }),
  adminListRedeemCodes: (params?: { status?: string; q?: string }) => {
    const qs = new URLSearchParams()
    if (params?.status) qs.set('status', params.status)
    if (params?.q) qs.set('q', params.q)
    const query = qs.toString()
    return request<RedeemCodeItem[]>(`/admin/redeem${query ? '?' + query : ''}`)
  },
  adminGenerateRedeemCodes: (payload: {
    count: number
    plan_id?: number
    balance_cents?: number
    quota_gb?: number
    duration_days?: number
    prefix?: string
    note?: string
  }) =>
    request<RedeemCodeItem[]>('/admin/redeem/generate', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  adminDeleteRedeemCode: (id: number) =>
    request<{ deleted: boolean }>(`/admin/redeem/${id}`, { method: 'DELETE' }),
  adminBatchDeleteRedeemCodes: (payload: { ids?: number[]; mode?: 'used' | 'unused' }) =>
    request<{ deleted: number }>('/admin/redeem/batch-delete', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  getOrders: (params?: { all?: boolean; status?: string; type?: string }) => {
    const qs = new URLSearchParams()
    if (params?.all) qs.set('all', '1')
    if (params?.status) qs.set('status', params.status)
    if (params?.type) qs.set('type', params.type)
    const query = qs.toString()
    return request<BillingOrder[]>(`/orders${query ? '?' + query : ''}`)
  },
  createRechargeOrder: (payload: {
    amount_cents: number
    gateway?: 'epay' | 'usdt' | 'manual'
    pay_type?: 'alipay' | 'wxpay' | 'qqpay' | 'usdt'
  }) =>
    request<BillingOrder>('/orders/recharge', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  adminConfirmOrder: (id: number) =>
    request<{ message: string; order: BillingOrder }>(`/admin/orders/${id}/confirm`, {
      method: 'POST',
    }),
  adminListAuditLogs: (params?: { action?: string; q?: string }) => {
    const qs = new URLSearchParams()
    if (params?.action && params.action !== 'all') qs.set('action', params.action)
    if (params?.q) qs.set('q', params.q)
    const query = qs.toString()
    return request<AuditLogItem[]>(`/admin/audit-logs${query ? '?' + query : ''}`)
  },
  adminDownloadSQLiteBackup: async () => {
    const token = localStorage.getItem('nexus_token')
    const res = await fetch(`${API_BASE}/admin/backup/sqlite`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
    if (!res.ok) {
      let errMsg = `导出失败 (${res.status})`
      try {
        const data = await res.json()
        if (data?.error) errMsg = data.error
      } catch {
        // ignore
      }
      throw new Error(errMsg)
    }
    const blob = await res.blob()
    const disposition = res.headers.get('Content-Disposition') || ''
    const match = disposition.match(/filename="?([^"]+)"?/)
    const filename = match?.[1] || `zachary-panel-backup-${Date.now()}.db`
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    return filename
  },
}

export interface AuditLogItem {
  id: number
  user_id: number
  user_email: string
  action: string
  target: string
  detail: string
  client_ip: string
  ip?: string
  created_at: string
}

export interface BillingOrder {
  id: number
  order_no: string
  user_id: number
  user_email: string
  type: 'recharge' | 'plan_purchase' | 'plan_reset' | 'redeem'
  plan_id: number
  plan_name: string
  amount_cents: number
  status: 'pending' | 'paid' | 'cancelled'
  gateway: 'balance' | 'epay' | 'usdt' | 'manual' | 'redeem'
  trade_no: string
  pay_url?: string
  created_at: string
  paid_at?: string
}

export function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${units[i]}`
}
