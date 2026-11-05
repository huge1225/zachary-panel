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
  sub_token?: string
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
  default_engine: EngineType
  supported_engines: string
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
  allowed_tunnels?: string
  active?: boolean
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
    throw new Error(data.error || `HTTP ${res.status}`)
  }
  return data as T
}

export const api = {
  getSiteConfig: () => request<SystemConfig>('/site-config'),

  login: (email: string, password: string) =>
    request<{ token: string; user: User }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
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
}

export function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${units[i]}`
}
