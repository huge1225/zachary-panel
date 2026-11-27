<script setup lang="ts">
import { ref, computed, watch, nextTick, onMounted, onUnmounted, type Ref } from 'vue'
import {
  api,
  formatBytes,
  safeExternalUrl,
  sanitizeExportField,
  sanitizeCSVCell,
  sanitizeDownloadFilename,
  type User,
  type NodeItem,
  type TunnelLine,
  type ForwardRule,
  type Plan,
  type RedeemCodeItem,
  type BillingOrder,
  type AuditLogItem,
  type RoleGroup,
  type EngineType,
  type LoadBalanceStrategy,
  type TargetEndpoint,
  type ProbeLeg,
  type IngressFailoverGroupItem,
  type SystemConfig,
  type CouponItem,
  type CouponPreviewResp,
  type AffiliateOverviewResp,
  type AffiliateWithdrawalItem,
  type SupportTicketItem,
  type TicketMessageItem,
} from './api/client'

const isDark = ref(
  typeof document !== 'undefined' && document.documentElement.classList.contains('dark'),
)
function toggleTheme() {
  isDark.value = !isDark.value
  document.documentElement.classList.toggle('dark', isDark.value)
  try {
    localStorage.setItem('nexus_theme', isDark.value ? 'dark' : 'light')
  } catch {
    // ignore storage quota errors
  }
}

function useDebouncedRef<T>(source: Ref<T>, delayMs = 220): Ref<T> {
  const debounced = ref(source.value) as Ref<T>
  let timer: ReturnType<typeof setTimeout> | null = null
  watch(source, (val) => {
    if (timer) clearTimeout(timer)
    timer = setTimeout(() => {
      debounced.value = val
    }, delayMs)
  })
  onUnmounted(() => {
    if (timer) clearTimeout(timer)
  })
  return debounced
}

const autoRefresh = ref(true)
const showMobileNav = ref(false)

const token = ref<string | null>(localStorage.getItem('nexus_token'))
const isRegisterMode = ref(false)
const emailInput = ref('')
const passwordInput = ref('')
const inviteCodeInput = ref('')
const authError = ref('')

type TabId =
  | 'dashboard'
  | 'rules'
  | 'lines'
  | 'nodes'
  | 'roles'
  | 'users'
  | 'store'
  | 'affiliate'
  | 'tickets'
  | 'settings'
const activeTab = ref<TabId>('dashboard')
const tabTitleMap: Record<string, string> = {
  dashboard: '概览',
  rules: '转发管理',
  lines: '隧道管理',
  nodes: '节点管理',
  roles: '角色管理',
  users: '用户管理',
  store: '套餐管理',
  affiliate: '推广返利',
  tickets: '工单客服',
  settings: '系统设置',
}
const currentTabTitle = computed(() => tabTitleMap[activeTab.value] || '')

function switchTab(tab: TabId) {
  activeTab.value = tab
  showMobileNav.value = false
  if (tab === 'settings') {
    syncSettingsForm()
  }
}

const siteConfig = ref<SystemConfig>({
  id: 1,
  site_name: 'Zachary Panel',
  site_logo: 'ZP',
  announcement: '深港 IEPL 专线状态稳定，角色决定可用隧道，套餐绑定角色，用户分配套餐与角色。',
  allow_register: false,
  default_quota_gb: 20,
  default_max_rules: 5,
  default_speed_mbps: 100,
  default_role_group_id: 1,
  default_tunnels: '1',
  affiliate_enabled: true,
  affiliate_commission_rate: 10,
  affiliate_min_withdraw_cents: 1000,
  offpeak_enabled: false,
  offpeak_start: '00:00',
  offpeak_end: '08:00',
  offpeak_multiplier: 0.5,
  offpeak_timezone: 'Asia/Shanghai',
})

const user = ref<User | null>(null)
const usersList = ref<User[]>([])
const rolesList = ref<RoleGroup[]>([])
const nodes = ref<NodeItem[]>([])
const lines = ref<TunnelLine[]>([])
const rules = ref<ForwardRule[]>([])
const plans = ref<Plan[]>([])
const redeemCodesList = ref<RedeemCodeItem[]>([])
const ordersList = ref<BillingOrder[]>([])
const auditLogsList = ref<AuditLogItem[]>([])
const couponsList = ref<CouponItem[]>([])
const affiliateOverview = ref<AffiliateOverviewResp | null>(null)
const adminWithdrawalsList = ref<AffiliateWithdrawalItem[]>([])
const ticketsList = ref<SupportTicketItem[]>([])
const dnsFailoverList = ref<IngressFailoverGroupItem[]>([])

const isAdmin = computed(() => user.value?.role === 'admin')

// O(1) lookup maps for high-density table rendering
const roleMap = computed(() => new Map(rolesList.value.map((r) => [r.id, r])))
const planMap = computed(() => new Map(plans.value.map((p) => [p.id, p])))
const nodeMap = computed(() => new Map(nodes.value.map((n) => [n.id, n])))
const lineMap = computed(() => new Map(lines.value.map((l) => [l.id, l])))
const userMap = computed(() => new Map(usersList.value.map((u) => [u.id, u])))

const lineRuleCountMap = computed(() => {
  const m = new Map<number, number>()
  for (const r of rules.value) {
    m.set(r.tunnel_line_id, (m.get(r.tunnel_line_id) || 0) + 1)
  }
  return m
})

const rolePlanCountMap = computed(() => {
  const m = new Map<number, number>()
  for (const p of plans.value) {
    m.set(p.role_group_id, (m.get(p.role_group_id) || 0) + 1)
  }
  return m
})

const roleUserCountMap = computed(() => {
  const m = new Map<number, number>()
  for (const u of usersList.value) {
    if (u.role !== 'admin' && u.role_group_id) {
      m.set(u.role_group_id, (m.get(u.role_group_id) || 0) + 1)
    }
  }
  return m
})

function parseAllowedIds(str?: string): number[] {
  if (!str) return []
  return str
    .split(',')
    .map((s) => Number(s.trim()))
    .filter((n) => n > 0)
}

function getRoleById(id?: number): RoleGroup | undefined {
  if (!id) return undefined
  return roleMap.value.get(id)
}

function roleNameById(id?: number): string {
  return getRoleById(id)?.name || '未分配角色'
}

function planNameById(id?: number): string {
  if (!id) return '自定义配额'
  return planMap.value.get(id)?.name || '自定义配额'
}

function allowedTunnelIdsForUser(u: User | null | undefined): number[] {
  if (!u) return []
  if (u.role === 'admin' || u.allowed_tunnels === '*') return lines.value.map((l) => l.id)
  const rg = getRoleById(u.role_group_id)
  if (rg) return parseAllowedIds(rg.allowed_tunnels)
  return parseAllowedIds(u.allowed_tunnels)
}

function userHasTunnel(u: User | null | undefined, tunnelId: number): boolean {
  if (!u) return false
  if (u.role === 'admin') return true
  const raw = (u.allowed_tunnels || '').trim()
  if (raw === '*') return true
  return allowedTunnelIdsForUser(u).includes(Number(tunnelId))
}

const authorizedLines = computed(() => {
  if (isAdmin.value) return lines.value
  return lines.value.filter((l) => userHasTunnel(user.value, l.id))
})

const visibleRules = computed(() => {
  if (isAdmin.value) return rules.value
  return rules.value.filter((r) => r.user_id === user.value?.id)
})

const ruleSearchQuery = ref('')
const debouncedRuleSearch = useDebouncedRef(ruleSearchQuery, 220)
const ruleFilterTunnelId = ref<number>(0)
const ruleFilterProtocol = ref<string>('all')
const ruleFilterStatus = ref<string>('all')
const rulesPage = ref(1)
const rulesPageSize = ref(20)

const filteredRules = computed(() => {
  const q = debouncedRuleSearch.value.trim().toLowerCase()
  return visibleRules.value.filter((r) => {
    if (ruleFilterTunnelId.value > 0 && r.tunnel_line_id !== ruleFilterTunnelId.value) return false
    if (ruleFilterProtocol.value !== 'all' && r.protocol !== ruleFilterProtocol.value) return false
    if (ruleFilterStatus.value === 'running' && !r.enabled) return false
    if (ruleFilterStatus.value === 'paused' && r.enabled) return false
    if (
      ruleFilterStatus.value === 'quota_exceeded' &&
      !['quota_exceeded', 'rule_quota_exceeded', 'daily_quota_exceeded'].includes(r.status)
    ) {
      return false
    }
    if (q) {
      const matchName = (r.name || '').toLowerCase().includes(q)
      const matchPort = String(r.listen_port).includes(q)
      const matchTarget = (r.targets_json || '').toLowerCase().includes(q)
      const matchDomain = (r.match_domains || '').toLowerCase().includes(q)
      const matchOutIP = (r.outbound_ip || '').toLowerCase().includes(q)
      const matchUser = isAdmin.value && userEmailById(r.user_id).toLowerCase().includes(q)
      if (!matchName && !matchPort && !matchTarget && !matchDomain && !matchOutIP && !matchUser) return false
    }
    return true
  })
})

const rulesTotalPages = computed(() => Math.max(1, Math.ceil(filteredRules.value.length / rulesPageSize.value)))
const pagedRules = computed(() => {
  const p = Math.min(rulesPage.value, rulesTotalPages.value)
  const start = (p - 1) * rulesPageSize.value
  return filteredRules.value.slice(start, start + rulesPageSize.value)
})
watch([debouncedRuleSearch, ruleFilterTunnelId, ruleFilterProtocol, ruleFilterStatus, rulesPageSize], () => {
  rulesPage.value = 1
})

const userSearchQuery = ref('')
const debouncedUserSearch = useDebouncedRef(userSearchQuery, 220)
const userFilterPlanId = ref<number>(-1)
const userFilterRoleId = ref<number>(-1)
const userFilterStatus = ref<string>('all')
const usersPage = ref(1)
const usersPageSize = ref(20)

const filteredUsersList = computed(() => {
  const q = debouncedUserSearch.value.trim().toLowerCase()
  return usersList.value.filter((u) => {
    if (userFilterPlanId.value >= 0 && (u.plan_id || 0) !== userFilterPlanId.value) return false
    if (userFilterRoleId.value >= 0 && (u.role_group_id || 0) !== userFilterRoleId.value) return false
    const expired = isUserExpired(u)
    const overQuota = u.quota_bytes > 0 && u.used_bytes >= u.quota_bytes
    if (userFilterStatus.value === 'banned' && u.status === 'active') return false
    if (userFilterStatus.value === 'expired' && (u.status !== 'active' || !expired)) return false
    if (userFilterStatus.value === 'over_quota' && (u.status !== 'active' || !overQuota)) return false
    if (userFilterStatus.value === 'active' && (u.status !== 'active' || expired || overQuota)) return false
    if (q) {
      const matchEmail = (u.email || '').toLowerCase().includes(q)
      const matchId = String(u.id) === q
      if (!matchEmail && !matchId) return false
    }
    return true
  })
})

const usersTotalPages = computed(() => Math.max(1, Math.ceil(filteredUsersList.value.length / usersPageSize.value)))
const pagedUsersList = computed(() => {
  const p = Math.min(usersPage.value, usersTotalPages.value)
  const start = (p - 1) * usersPageSize.value
  return filteredUsersList.value.slice(start, start + usersPageSize.value)
})
watch([debouncedUserSearch, userFilterPlanId, userFilterRoleId, userFilterStatus, usersPageSize], () => {
  usersPage.value = 1
})

const toastMsg = ref('')
let toastTimer: ReturnType<typeof setTimeout> | null = null
function showToast(msg: string) {
  toastMsg.value = msg
  if (toastTimer) clearTimeout(toastTimer)
  toastTimer = setTimeout(() => {
    toastMsg.value = ''
  }, 2000)
}

function copyConnectAddr(text: string) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => {
      showToast(`已复制: ${text}`)
    })
  }
}

function loadBalanceLabel(lb?: string): string {
  switch (lb) {
    case 'weighted':
      return '加权调度'
    case 'least_rtt':
      return '最低延迟'
    case 'failover':
      return '主备容灾'
    case 'random':
      return '随机调度'
    default:
      return '轮询'
  }
}

function parseTargetLine(rawLine: string): TargetEndpoint | null {
  const trimmed = rawLine.trim()
  if (!trimmed) return null
  if (trimmed.includes('|')) {
    const parts = trimmed.split('|').map((s) => s.trim())
    const address = parts[0] || ''
    if (!address) return null
    const ep: TargetEndpoint = { address }
    for (let i = 1; i < parts.length; i++) {
      const tok = (parts[i] || '').toLowerCase()
      if (tok === 'backup') ep.backup = true
      else if (/^\d+$/.test(tok)) ep.weight = Number(tok)
    }
    return ep
  }
  const [addrPart, ...metaParts] = trimmed.split('#').map((s) => s.trim())
  if (!addrPart) return null
  const ep: TargetEndpoint = { address: addrPart }
  for (const meta of metaParts) {
    for (const token of meta.split(',').map((s) => s.trim().toLowerCase())) {
      if (!token) continue
      if (token === 'backup') {
        ep.backup = true
      } else if (token.startsWith('weight=')) {
        const w = Number(token.slice(7))
        if (w > 0) ep.weight = w
      } else if (/^\d+$/.test(token)) {
        ep.weight = Number(token)
      }
    }
  }
  return ep
}

function formatTargetLine(t: TargetEndpoint): string {
  const tags: string[] = []
  if (t.weight && t.weight > 0 && t.weight !== 100) tags.push(`weight=${t.weight}`)
  if (t.backup) tags.push('backup')
  return tags.length > 0 ? `${t.address}#${tags.join(',')}` : t.address
}

function ruleStatusLabel(rule: ForwardRule): string {
  if (rule.enabled) return '正常'
  switch (rule.status) {
    case 'daily_quota_exceeded':
      return '今日限额耗尽'
    case 'rule_quota_exceeded':
      return '规则限额耗尽'
    case 'quota_exceeded':
      return '套餐流量耗尽'
    case 'node_quota_exceeded':
      return '节点流量耗尽'
    case 'error':
      return '端口/配置异常'
    default:
      return '已暂停'
  }
}

function ruleStatusBadge(rule: ForwardRule): string {
  if (rule.enabled) return 'badge-success'
  if (
    ['daily_quota_exceeded', 'rule_quota_exceeded', 'quota_exceeded', 'node_quota_exceeded'].includes(
      rule.status,
    )
  ) {
    return 'badge-warning'
  }
  if (rule.status === 'error') return 'badge-danger'
  return 'badge-neutral'
}

function effectiveRuleProxyProto(rule: ForwardRule): number {
  const rpp = Number(rule.proxy_protocol || 0)
  if (rpp < 0) return 0
  if (rpp === 1 || rpp === 2) return rpp
  const line = getTunnelById(rule.tunnel_line_id)
  return Number(line?.proxy_protocol || 0)
}

// --- 转发新增与编辑 ---
const GB = 1024 * 1024 * 1024
const showRuleModal = ref(false)
const editingRuleId = ref<number | null>(null)
const ruleForm = ref({
  name: '',
  tunnel_line_id: 1,
  protocol: 'tcp' as 'tcp' | 'udp' | 'both',
  listen_port: 0,
  load_balance: 'round_robin' as LoadBalanceStrategy,
  targetsText: '1.1.1.1:443',
  speed_mbps: 0,
  access_mode: 'off' as 'off' | 'allow' | 'deny',
  access_cidrs: '',
  match_domains: '',
  proxy_protocol: 0,
  outbound_ip: '',
  rule_quota_gb: 0,
  daily_quota_gb: 0,
})

// 当前选中隧道（或其入口节点）的可用端口范围，用于监听端口输入提示
const selectedRuleFormLine = computed(() =>
  lines.value.find((l) => l.id === ruleForm.value.tunnel_line_id),
)

const ruleFormPortHint = computed(() => {
  const line = selectedRuleFormLine.value
  if (!line) return '留空自动分配'
  const range = line.port_range || nodes.value.find((n) => n.id === line.ingress_node_id)?.port_range || ''
  return range ? `留空自动分配（${range}）` : '留空自动分配'
})

const ruleFormAllowedOutboundIPs = computed(() => {
  const raw = selectedRuleFormLine.value?.allowed_outbound_ips || ''
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
})

function openCreateRuleModal() {
  if (authorizedLines.value.length === 0) {
    showToast('当前账号暂无可用隧道权限，请联系管理员分配')
    return
  }
  editingRuleId.value = null
  ruleForm.value = {
    name: '',
    tunnel_line_id: authorizedLines.value[0]?.id || 1,
    protocol: 'tcp',
    listen_port: 0,
    load_balance: 'round_robin',
    targetsText: '1.1.1.1:443',
    speed_mbps: 0,
    access_mode: 'off',
    access_cidrs: '',
    match_domains: '',
    proxy_protocol: 0,
    outbound_ip: '',
    rule_quota_gb: 0,
    daily_quota_gb: 0,
  }
  showRuleModal.value = true
}

function openEditRuleModal(rule: ForwardRule) {
  if (!isAdmin.value && rule.user_id !== user.value?.id) {
    showToast('禁止越权操作他人规则')
    return
  }
  editingRuleId.value = rule.id
  const targets = parseTargets(rule.targets_json)
  ruleForm.value = {
    name: rule.name,
    tunnel_line_id: rule.tunnel_line_id,
    protocol: rule.protocol,
    listen_port: rule.listen_port,
    load_balance: rule.load_balance || 'round_robin',
    targetsText: targets.map((t) => formatTargetLine(t)).join('\n'),
    speed_mbps: rule.speed_mbps,
    access_mode: (rule.access_mode as 'off' | 'allow' | 'deny') || 'off',
    access_cidrs: rule.access_cidrs || '',
    match_domains: rule.match_domains || '',
    proxy_protocol: Number(rule.proxy_protocol || 0),
    outbound_ip: rule.outbound_ip || '',
    rule_quota_gb: rule.rule_quota_bytes ? Number((rule.rule_quota_bytes / GB).toFixed(2)) : 0,
    daily_quota_gb: rule.daily_quota_bytes ? Number((rule.daily_quota_bytes / GB).toFixed(2)) : 0,
  }
  showRuleModal.value = true
}

function quickCreateRuleForTunnel(line: TunnelLine) {
  if (!userHasTunnel(user.value, line.id)) {
    showToast('无该隧道的使用权限')
    return
  }
  activeTab.value = 'rules'
  editingRuleId.value = null
  ruleForm.value = {
    name: '',
    tunnel_line_id: line.id,
    protocol: 'tcp',
    listen_port: 0,
    load_balance: 'round_robin',
    targetsText: '1.1.1.1:443',
    speed_mbps: 0,
    access_mode: 'off',
    access_cidrs: '',
    match_domains: '',
    proxy_protocol: 0,
    outbound_ip: '',
    rule_quota_gb: 0,
    daily_quota_gb: 0,
  }
  showRuleModal.value = true
}

// --- 隧道新增与编辑 (支持多跳链式转发 + 多出口带宽聚合池 + Mux / Bonding + PROXY Protocol + 专属闲时倍率) ---
const showLineModal = ref(false)
const editingLineId = ref<number | null>(null)
const hopPickerNodeId = ref<number>(0)
const egressPoolPickerNodeId = ref<number>(0)
const egressPoolPickerWeight = ref<number>(100)
const egressPoolPickerBackup = ref<boolean>(false)
const lineForm = ref({
  name: '',
  type: 'direct' as 'direct' | 'encrypt',
  ingress_node_id: 1,
  hop_node_ids: '',
  egress_node_id: 2,
  egress_node_ids: '',
  load_balance: 'round_robin' as LoadBalanceStrategy,
  accel_mode: 'none' as 'none' | 'mux' | 'bonding',
  bond_links: 4,
  proxy_protocol: 0,
  offpeak_multiplier: 0,
  transport: 'tls' as 'raw' | 'tls' | 'ws' | 'wss' | 'quic' | 'custom',
  engine: 'realm' as EngineType,
  billing_mode: 'one_way' as 'one_way' | 'two_way',
  rate_multiplier: 1.0,
  max_port_count: 50,
  port_range: '',
})

const lineHopIds = computed(() => parseAllowedIds(lineForm.value.hop_node_ids))

function addHopToLineForm() {
  const nid = Number(hopPickerNodeId.value)
  if (!nid) return
  if (nid === lineForm.value.ingress_node_id) {
    showToast('中间跳点不能与入口节点相同')
    return
  }
  if (lineHopIds.value.includes(nid)) {
    showToast('该节点已在链式跳点列表中')
    return
  }
  if (lineHopIds.value.length >= 8) {
    showToast('单条隧道最多支持 8 个中间跳点')
    return
  }
  lineForm.value.hop_node_ids = [...lineHopIds.value, nid].join(',')
}

function removeHopFromLineForm(idx: number) {
  const next = lineHopIds.value.filter((_, i) => i !== idx)
  lineForm.value.hop_node_ids = next.join(',')
}

function moveHopInLineForm(idx: number, delta: number) {
  const arr = [...lineHopIds.value]
  const target = idx + delta
  if (target < 0 || target >= arr.length) return
  const tmp = arr[idx]
  arr[idx] = arr[target]
  arr[target] = tmp
  lineForm.value.hop_node_ids = arr.join(',')
}

function addMemberToEgressPool() {
  const nid = Number(egressPoolPickerNodeId.value)
  if (!nid) return
  const w = Math.max(1, Math.min(10000, Math.round(Number(egressPoolPickerWeight.value) || 100)))
  const token = egressPoolPickerBackup.value ? `${nid}:${w}:backup` : `${nid}:${w}`
  const existing = (lineForm.value.egress_node_ids || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
  if (existing.some((item) => Number(item.split(':')[0]) === nid)) {
    showToast('该出口节点已在多出口聚合池中')
    return
  }
  existing.push(token)
  lineForm.value.egress_node_ids = existing.join(',')
}

function parseLineEgressCount(line: TunnelLine): number {
  if (!line.egress_node_ids) return line.egress_node_id ? 1 : 0
  return line.egress_node_ids
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean).length
}

function openCreateLineModal() {
  if (!isAdmin.value) return
  editingLineId.value = null
  const firstId = nodes.value[0]?.id || 1
  const lastId = nodes.value[nodes.value.length - 1]?.id || firstId
  hopPickerNodeId.value = nodes.value[1]?.id || firstId
  egressPoolPickerNodeId.value = lastId
  egressPoolPickerWeight.value = 100
  egressPoolPickerBackup.value = false
  lineForm.value = {
    name: '',
    type: 'direct',
    ingress_node_id: firstId,
    hop_node_ids: '',
    egress_node_id: lastId,
    egress_node_ids: '',
    load_balance: 'round_robin',
    accel_mode: 'none',
    bond_links: 4,
    proxy_protocol: 0,
    offpeak_multiplier: 0,
    transport: 'tls',
    engine: 'realm',
    billing_mode: 'one_way',
    rate_multiplier: 1.0,
    max_port_count: 50,
    port_range: '',
  }
  showLineModal.value = true
}

function openEditLineModal(line: TunnelLine) {
  if (!isAdmin.value) return
  editingLineId.value = line.id
  hopPickerNodeId.value = nodes.value[0]?.id || 1
  egressPoolPickerNodeId.value = line.egress_node_id || nodes.value[0]?.id || 1
  egressPoolPickerWeight.value = 100
  egressPoolPickerBackup.value = false
  lineForm.value = {
    name: line.name,
    type: line.type,
    ingress_node_id: line.ingress_node_id,
    hop_node_ids: line.hop_node_ids || '',
    egress_node_id: line.egress_node_id || nodes.value[0]?.id || 1,
    egress_node_ids: line.egress_node_ids || '',
    load_balance: line.load_balance || 'round_robin',
    accel_mode: line.enable_bonding ? 'bonding' : line.enable_mux ? 'mux' : 'none',
    bond_links: line.bond_links || 4,
    proxy_protocol: Number(line.proxy_protocol || 0),
    offpeak_multiplier: Number(line.offpeak_multiplier || 0),
    transport: line.transport || 'tls',
    engine: line.engine,
    billing_mode: line.billing_mode || 'one_way',
    rate_multiplier: line.rate_multiplier,
    max_port_count: line.max_port_count || 50,
    port_range: line.port_range || '',
  }
  showLineModal.value = true
}

// --- 节点新增与编辑 (支持默认出站源 IP、授权出站 IP 白名单与维护模式) ---
const showNodeModal = ref(false)
const editingNodeId = ref<number | null>(null)
const nodeForm = ref({
  name: '',
  connect_ip: '',
  server_ip: '',
  outbound_ip: '',
  allowed_outbound_ips: '',
  maintenance: false,
  port_range: '10000-50000',
  traffic_rate: 1.0,
  quota_gb: 2000,
  used_gb: 0,
  reset_day: 0,
})

function openCreateNodeModal() {
  if (!isAdmin.value) return
  editingNodeId.value = null
  nodeForm.value = {
    name: '',
    connect_ip: '',
    server_ip: '',
    outbound_ip: '',
    allowed_outbound_ips: '',
    maintenance: false,
    port_range: '10000-50000',
    traffic_rate: 1.0,
    quota_gb: 2000,
    used_gb: 0,
    reset_day: 0,
  }
  showNodeModal.value = true
}

function openEditNodeModal(node: NodeItem) {
  if (!isAdmin.value) return
  editingNodeId.value = node.id
  nodeForm.value = {
    name: node.name,
    connect_ip: node.connect_ip || node.public_host,
    server_ip: node.server_ip,
    outbound_ip: node.outbound_ip || '',
    allowed_outbound_ips: node.allowed_outbound_ips || '',
    maintenance: node.status === 'maintenance',
    port_range: node.port_range,
    traffic_rate: node.traffic_rate,
    quota_gb: Math.round((node.quota_bytes || 0) / GB),
    used_gb: Number(((node.used_bytes || 0) / GB).toFixed(1)),
    reset_day: node.reset_day || 0,
  }
  showNodeModal.value = true
}

// --- 多入口高可用与 DNS 自动容灾切换 (IngressFailoverGroup) ---
const showFailoverModal = ref(false)
const editingFailoverId = ref<number | null>(null)
const failoverBackupPickerId = ref<number>(0)
const reconcilingFailoverId = ref<number | null>(null)
const failoverForm = ref({
  name: '',
  domain: '',
  record_type: 'A' as 'A' | 'AAAA',
  ttl: 60,
  proxied: false,
  primary_node_id: 1,
  backup_node_ids: '',
  provider: 'cloudflare' as 'cloudflare' | 'dnspod' | 'webhook',
  zone_id: '',
  record_id: '',
  sub_domain: '',
  api_token: '',
  webhook_url: '',
  offline_threshold_sec: 30,
  cooldown_sec: 120,
  auto_failback: true,
  enabled: true,
  has_api_token: false,
})

const failoverBackupIds = computed(() => parseAllowedIds(failoverForm.value.backup_node_ids))

function addFailoverBackupNode() {
  const nid = Number(failoverBackupPickerId.value)
  if (!nid) return
  if (nid === failoverForm.value.primary_node_id) {
    showToast('备用入口节点不能与主入口节点相同')
    return
  }
  if (failoverBackupIds.value.includes(nid)) {
    showToast('该节点已在备用入口队列中')
    return
  }
  failoverForm.value.backup_node_ids = [...failoverBackupIds.value, nid].join(',')
}

function removeFailoverBackupNode(idx: number) {
  failoverForm.value.backup_node_ids = failoverBackupIds.value.filter((_, i) => i !== idx).join(',')
}

function openCreateFailoverModal() {
  if (!isAdmin.value) return
  editingFailoverId.value = null
  const primaryId = nodes.value[0]?.id || 1
  const secondId = nodes.value.find((n) => n.id !== primaryId)?.id || 0
  failoverBackupPickerId.value = secondId || primaryId
  failoverForm.value = {
    name: '',
    domain: '',
    record_type: 'A',
    ttl: 60,
    proxied: false,
    primary_node_id: primaryId,
    backup_node_ids: secondId ? String(secondId) : '',
    provider: 'cloudflare',
    zone_id: '',
    record_id: '',
    sub_domain: '',
    api_token: '',
    webhook_url: '',
    offline_threshold_sec: 30,
    cooldown_sec: 120,
    auto_failback: true,
    enabled: true,
    has_api_token: false,
  }
  showFailoverModal.value = true
}

function openEditFailoverModal(g: IngressFailoverGroupItem) {
  if (!isAdmin.value) return
  editingFailoverId.value = g.id
  failoverBackupPickerId.value = nodes.value.find((n) => n.id !== g.primary_node_id)?.id || g.primary_node_id
  failoverForm.value = {
    name: g.name,
    domain: g.domain,
    record_type: g.record_type || 'A',
    ttl: g.ttl || 60,
    proxied: Boolean(g.proxied),
    primary_node_id: g.primary_node_id,
    backup_node_ids: g.backup_node_ids || '',
    provider: g.provider || 'cloudflare',
    zone_id: g.zone_id || '',
    record_id: g.record_id || '',
    sub_domain: g.sub_domain || '',
    api_token: '',
    webhook_url: g.webhook_url || '',
    offline_threshold_sec: g.offline_threshold_sec ?? 30,
    cooldown_sec: g.cooldown_sec ?? 120,
    auto_failback: Boolean(g.auto_failback),
    enabled: Boolean(g.enabled),
    has_api_token: Boolean(g.has_api_token),
  }
  showFailoverModal.value = true
}

async function submitFailoverForm() {
  if (!isAdmin.value) return
  const f = failoverForm.value
  const payload: Record<string, unknown> = {
    name: f.name.trim(),
    domain: f.domain.trim(),
    record_type: f.record_type,
    ttl: Math.max(1, Math.round(Number(f.ttl) || 60)),
    proxied: Boolean(f.proxied),
    primary_node_id: Number(f.primary_node_id) || 0,
    backup_node_ids: f.backup_node_ids.trim(),
    provider: f.provider,
    zone_id: f.zone_id.trim(),
    record_id: f.record_id.trim(),
    sub_domain: f.sub_domain.trim(),
    webhook_url: f.webhook_url.trim(),
    offline_threshold_sec: Math.max(0, Math.round(Number(f.offline_threshold_sec) || 0)),
    cooldown_sec: Math.max(0, Math.round(Number(f.cooldown_sec) || 0)),
    auto_failback: Boolean(f.auto_failback),
    enabled: Boolean(f.enabled),
  }
  if (f.api_token.trim() || !editingFailoverId.value) {
    payload.api_token = f.api_token.trim()
  }
  try {
    if (editingFailoverId.value) {
      await api.adminUpdateDNSFailover(editingFailoverId.value, payload)
      showToast('DNS 容灾组配置已更新')
    } else {
      await api.adminCreateDNSFailover(payload)
      showToast('DNS 容灾组已创建')
    }
    showFailoverModal.value = false
    dnsFailoverList.value = await api.adminListDNSFailover().catch(() => dnsFailoverList.value)
  } catch (e: any) {
    showToast(e.message)
  }
}

async function reconcileFailoverGroup(g: IngressFailoverGroupItem) {
  if (!isAdmin.value) return
  reconcilingFailoverId.value = g.id
  try {
    const res = await api.adminReconcileDNSFailover(g.id)
    const idx = dnsFailoverList.value.findIndex((x) => x.id === g.id)
    if (idx >= 0 && res.group) {
      dnsFailoverList.value[idx] = res.group
    }
    showToast(res.message || '已完成巡检与同步')
  } catch (e: any) {
    showToast(e.message)
  } finally {
    reconcilingFailoverId.value = null
  }
}

async function deleteFailoverGroup(g: IngressFailoverGroupItem) {
  if (!isAdmin.value) return
  if (!window.confirm(`确定删除多入口 DNS 容灾组「${g.name}」(${g.domain}) 吗？`)) return
  try {
    await api.adminDeleteDNSFailover(g.id)
    dnsFailoverList.value = dnsFailoverList.value.filter((x) => x.id !== g.id)
    showToast(`已删除容灾组「${g.name}」`)
  } catch (e: any) {
    showToast(e.message)
  }
}

const probeResults = ref<Record<number, { tunnel_ms?: number; latencies: Record<string, number>; legs?: ProbeLeg[] }>>({})
const probingRuleId = ref<number | null>(null)
const showInstallModal = ref(false)
const installMode = ref<'systemd' | 'docker'>('systemd')
const installInfo = ref<{
  node_id: number
  install_cmd: string
  systemd_install: string
  systemd_uninstall: string
  docker_install: string
  docker_uninstall: string
  direct_run?: string
  warnings?: string[]
} | null>(null)
const redeemInput = ref('')

function nodeTrafficPercent(node: NodeItem): number {
  if (!node.quota_bytes || node.quota_bytes <= 0) return 0
  return Math.min(100, Number((((node.used_bytes || 0) / node.quota_bytes) * 100).toFixed(1)))
}

function formatUptime(sec: number): string {
  if (!sec || sec <= 0) return '0分钟'
  const days = Math.floor(sec / 86400)
  const hours = Math.floor((sec % 86400) / 3600)
  if (days > 0) return `${days}天 ${hours}小时`
  const mins = Math.floor((sec % 3600) / 60)
  return `${hours}小时 ${mins}分`
}

// --- 规则批量导入、导出与批量删除 ---
const showBatchModal = ref(false)
const batchFileInput = ref<HTMLInputElement | null>(null)
const batchForm = ref({
  tunnel_line_id: 1,
  protocol: 'tcp' as 'tcp' | 'udp' | 'both',
  rawText: '业务节点A|0|1.1.1.1:443\n业务节点B|0|8.8.8.8:53',
})

const selectedRuleIds = ref<number[]>([])
const validSelectedRuleIds = computed(() => {
  const visibleSet = new Set(filteredRules.value.map((r) => r.id))
  return selectedRuleIds.value.filter((id) => visibleSet.has(id))
})
const allVisibleSelected = computed(
  () =>
    pagedRules.value.length > 0 &&
    pagedRules.value.every((r) => selectedRuleIds.value.includes(r.id)),
)

function toggleSelectAllRules(e: Event) {
  const checked = (e.target as HTMLInputElement).checked
  const pageIds = pagedRules.value.map((r) => r.id)
  if (checked) {
    const merged = new Set([...selectedRuleIds.value, ...pageIds])
    selectedRuleIds.value = Array.from(merged)
  } else {
    const pageSet = new Set(pageIds)
    selectedRuleIds.value = selectedRuleIds.value.filter((id) => !pageSet.has(id))
  }
}

async function handleBatchDeleteRules() {
  const ids = validSelectedRuleIds.value
  if (ids.length === 0) {
    showToast('请先勾选要删除的规则')
    return
  }
  if (!window.confirm(`确认删除选中的 ${ids.length} 条转发规则吗？`)) {
    return
  }
  try {
    const res = await api.batchDeleteRules(ids)
    const deletedSet = new Set(res.ids || ids)
    rules.value = rules.value.filter((r) => !deletedSet.has(r.id))
    selectedRuleIds.value = selectedRuleIds.value.filter((id) => !deletedSet.has(id))
    showToast(`已批量删除 ${res.deleted} 条规则`)
  } catch (e: any) {
    showToast(e.message)
  }
}

function openBatchModal() {
  if (authorizedLines.value.length === 0) {
    showToast('当前账号暂无可用隧道权限')
    return
  }
  batchForm.value = {
    tunnel_line_id: authorizedLines.value[0]?.id || 1,
    protocol: 'tcp',
    rawText: '业务节点A|0|1.1.1.1:443\n业务节点B|0|8.8.8.8:53',
  }
  showBatchModal.value = true
}

function parseBatchRuleItems(rawText: string): Array<{
  name: string
  listen_port: number
  port_range?: string
  targets: TargetEndpoint[]
  protocol?: 'tcp' | 'udp' | 'both'
  load_balance?: LoadBalanceStrategy
}> {
  const trimmed = rawText.trim()
  if (!trimmed) return []
  if (trimmed.startsWith('[')) {
    try {
      const arr = JSON.parse(trimmed)
      if (Array.isArray(arr)) {
        return arr
          .map((item, idx) => {
            if (!item || typeof item !== 'object') return null
            const name = String(item.name || `批量规则-${idx + 1}`).trim()
            const listen_port = Number(item.listen_port) || 0
            let targets: TargetEndpoint[] = []
            if (Array.isArray(item.targets)) {
              targets = item.targets
                .map((t: any) => ({ address: String(typeof t === 'string' ? t : t?.address || '').trim() }))
                .filter((t: TargetEndpoint) => Boolean(t.address))
            } else if (typeof item.targets_json === 'string') {
              targets = parseTargets(item.targets_json)
            } else if (typeof item.target === 'string' && item.target.trim()) {
              targets = item.target
                .split(',')
                .map((s: string) => ({ address: s.trim() }))
                .filter((t: TargetEndpoint) => Boolean(t.address))
            }
            if (targets.length === 0) return null
            const proto = ['tcp', 'udp', 'both'].includes(String(item.protocol || '').toLowerCase())
              ? (String(item.protocol).toLowerCase() as 'tcp' | 'udp' | 'both')
              : undefined
            const lb = ['round_robin', 'weighted', 'least_rtt', 'failover', 'random'].includes(
              String(item.load_balance || ''),
            )
              ? (String(item.load_balance) as LoadBalanceStrategy)
              : undefined
            const port_range = item.port_range ? String(item.port_range).trim() : undefined
            return { name, listen_port, port_range, targets, protocol: proto, load_balance: lb }
          })
          .filter(Boolean) as Array<{
          name: string
          listen_port: number
          port_range?: string
          targets: TargetEndpoint[]
          protocol?: 'tcp' | 'udp' | 'both'
          load_balance?: LoadBalanceStrategy
        }>
      }
    } catch {
      // fall through to line parser
    }
  }

  const rows = trimmed
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => Boolean(s) && !s.startsWith('#'))
  return rows
    .map((row, idx) => {
      const sep = row.includes('|') ? '|' : ','
      const parts = row.split(sep).map((s) => s.trim())
      if (parts.length < 2) return null
      const name = parts.length >= 3 ? parts[0] : `批量规则-${idx + 1}`
      const portToken = parts.length >= 3 ? parts[1] : parts[0]
      const isRange = /^\d+\s*-\s*\d+$/.test(portToken || '')
      const listen_port = isRange ? 0 : Number(portToken) || 0
      const port_range = isRange ? portToken.replace(/\s+/g, '') : undefined
      const rawAddr = parts.length >= 3 ? parts[2] : parts[1]
      const targets = (rawAddr || '')
        .split(';')
        .map((a) => ({ address: a.trim() }))
        .filter((t) => Boolean(t.address))
      if (targets.length === 0) return null
      const protoRaw = parts.length >= 4 ? (parts[3] || '').toLowerCase() : ''
      const protocol = ['tcp', 'udp', 'both'].includes(protoRaw)
        ? (protoRaw as 'tcp' | 'udp' | 'both')
        : undefined
      return { name, listen_port, port_range, targets, protocol }
    })
    .filter(Boolean) as Array<{
    name: string
    listen_port: number
    port_range?: string
    targets: TargetEndpoint[]
    protocol?: 'tcp' | 'udp' | 'both'
  }>
}

function handleBatchFileSelect(e: Event) {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  if (file.size > 1024 * 1024) {
    showToast('导入文件大小不能超过 1MB')
    input.value = ''
    return
  }
  const reader = new FileReader()
  reader.onload = () => {
    batchForm.value.rawText = String(reader.result || '')
    showToast(`已读取文件 ${sanitizeExportField(file.name, 80)}`)
  }
  reader.readAsText(file)
  input.value = ''
}

async function submitBatchRules() {
  if (!userHasTunnel(user.value, batchForm.value.tunnel_line_id)) {
    showToast('无权在该隧道下导入规则')
    return
  }
  const items = parseBatchRuleItems(batchForm.value.rawText)
  if (items.length === 0) {
    showToast('请输入有效规则')
    return
  }
  try {
    const created = await api.batchCreateRules({
      tunnel_line_id: batchForm.value.tunnel_line_id,
      protocol: batchForm.value.protocol,
      items,
    })
    showBatchModal.value = false
    showToast(`成功批量导入 ${created.length} 条规则`)
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

function downloadSafeCSV(filename: string, headers: string[], rows: unknown[][]) {
  const safeName = sanitizeDownloadFilename(filename, 'export.csv')
  const csvLines = [
    headers.map((h) => sanitizeCSVCell(h, 64)).join(','),
    ...rows.map((row) => row.map((cell) => sanitizeCSVCell(cell, 512)).join(',')),
  ]
  const blob = new Blob(['\uFEFF' + csvLines.join('\r\n')], {
    type: 'text/csv;charset=utf-8',
  })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = safeName
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

function exportRulesToClipboard() {
  const source =
    validSelectedRuleIds.value.length > 0
      ? filteredRules.value.filter((r) => validSelectedRuleIds.value.includes(r.id))
      : filteredRules.value
  const text = source
    .map((r) => {
      const addrs = parseTargets(r.targets_json)
        .map((t) => sanitizeExportField(t.address, 255))
        .filter(Boolean)
        .join(';')
      const safeName = sanitizeExportField(r.name, 64)
      const safeProto = sanitizeExportField(r.protocol || 'tcp', 16)
      return `${safeName}|${Number(r.listen_port) || 0}|${addrs}|${safeProto}`
    })
    .join('\n')
  copyConnectAddr(text)
  showToast(`已安全导出 ${source.length} 条规则到剪贴板`)
}

function exportRulesToCSV() {
  const source =
    validSelectedRuleIds.value.length > 0
      ? filteredRules.value.filter((r) => validSelectedRuleIds.value.includes(r.id))
      : filteredRules.value
  if (source.length === 0) {
    showToast('当前没有可导出的规则')
    return
  }
  downloadSafeCSV(
    `zachary-rules-${new Date().toISOString().slice(0, 10)}.csv`,
    ['ID', '规则名称', '协议', '入口端口', '目标地址', '状态', '计费流量'],
    source.map((r) => [
      r.id,
      r.name,
      r.protocol,
      r.listen_port,
      parseTargets(r.targets_json).map((t) => t.address).join(';'),
      r.status,
      formatBytes(r.billed_bytes),
    ]),
  )
  showToast(`已导出 ${source.length} 条规则 CSV 文件`)
}

// --- 角色管理 (管理员：角色决定可用隧道) ---
const showRoleModal = ref(false)
const editingRoleId = ref<number | null>(null)
const roleForm = ref({
  id: 0,
  name: '',
  description: '',
  tunnelIds: [] as number[],
})

function openCreateRoleModal() {
  if (!isAdmin.value) return
  editingRoleId.value = null
  roleForm.value = {
    id: 0,
    name: '',
    description: '',
    tunnelIds: lines.value[0] ? [lines.value[0].id] : [],
  }
  showRoleModal.value = true
}

function openEditRoleModal(rg: RoleGroup) {
  if (!isAdmin.value) return
  editingRoleId.value = rg.id
  roleForm.value = {
    id: rg.id,
    name: rg.name,
    description: rg.description || '',
    tunnelIds: parseAllowedIds(rg.allowed_tunnels),
  }
  showRoleModal.value = true
}

async function submitRoleForm() {
  if (!isAdmin.value) return
  if (!roleForm.value.name.trim()) {
    showToast('请输入角色名称')
    return
  }
  const allowedStr = roleForm.value.tunnelIds.join(',')
  try {
    if (editingRoleId.value) {
      await api.adminUpdateRole(editingRoleId.value, {
        name: roleForm.value.name.trim(),
        description: roleForm.value.description.trim(),
        allowed_tunnels: allowedStr,
      })
      showToast('角色已更新，绑定该角色的套餐与用户隧道权限已同步')
    } else {
      await api.adminCreateRole({
        name: roleForm.value.name.trim(),
        description: roleForm.value.description.trim(),
        allowed_tunnels: allowedStr,
      })
      showToast('角色已创建')
    }
    showRoleModal.value = false
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

async function deleteRoleGroup(rg: RoleGroup) {
  if (!isAdmin.value) return
  try {
    await api.adminDeleteRole(rg.id)
    showToast(`已删除角色「${rg.name}」`)
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

// --- 套餐管理 (管理员：套餐绑定角色) ---
const showPlanModal = ref(false)
const editingPlanId = ref<number | null>(null)
const planForm = ref({
  id: 0,
  name: '',
  price_yuan: 19.9,
  duration_days: 30,
  quota_gb: 200,
  max_rules: 10,
  speed_mbps: 200,
  role_group_id: 1,
  monthly_reset: false,
})

function openCreatePlanModal() {
  if (!isAdmin.value) return
  editingPlanId.value = null
  planForm.value = {
    id: 0,
    name: '',
    price_yuan: 29.9,
    duration_days: 30,
    quota_gb: 300,
    max_rules: 15,
    speed_mbps: 300,
    role_group_id: rolesList.value[0]?.id || 1,
    monthly_reset: false,
  }
  showPlanModal.value = true
}

function openEditPlanModal(p: Plan) {
  if (!isAdmin.value) return
  editingPlanId.value = p.id
  planForm.value = {
    id: p.id,
    name: p.name,
    price_yuan: Number(((p.price_cents || 0) / 100).toFixed(2)),
    duration_days: p.duration_days || 30,
    quota_gb: Math.round((p.quota_bytes || 0) / GB),
    max_rules: p.max_rules || 10,
    speed_mbps: p.speed_mbps || 100,
    role_group_id: p.role_group_id || rolesList.value[0]?.id || 1,
    monthly_reset: Boolean(p.monthly_reset),
  }
  showPlanModal.value = true
}

async function submitPlanForm() {
  if (!isAdmin.value) return
  if (!planForm.value.name.trim()) {
    showToast('请输入套餐名称')
    return
  }
  const payload = {
    name: planForm.value.name.trim(),
    price_cents: Math.round((Number(planForm.value.price_yuan) || 0) * 100),
    duration_days: Math.max(1, Number(planForm.value.duration_days) || 30),
    quota_bytes: Math.max(1, Number(planForm.value.quota_gb) || 100) * GB,
    max_rules: Math.max(1, Number(planForm.value.max_rules) || 10),
    speed_mbps: Math.max(10, Number(planForm.value.speed_mbps) || 100),
    role_group_id: Number(planForm.value.role_group_id) || 1,
    monthly_reset: Boolean(planForm.value.monthly_reset),
  }
  try {
    if (editingPlanId.value) {
      await api.adminUpdatePlan(editingPlanId.value, payload)
      showToast('套餐配置与绑定角色已更新')
    } else {
      await api.adminCreatePlan(payload)
      showToast('新增套餐成功')
    }
    showPlanModal.value = false
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

async function deletePlanItem(p: Plan) {
  if (!isAdmin.value) return
  try {
    await api.adminDeletePlan(p.id)
    showToast(`已删除套餐「${p.name}」`)
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

// --- 用户与套餐/角色分配管理 (管理员) ---
const showUserModal = ref(false)
const editingUserId = ref<number | null>(null)
const userForm = ref({
  id: 0,
  email: '',
  password: '',
  role: 'user' as 'admin' | 'user',
  plan_id: 1,
  role_group_id: 1,
  quota_gb: 100,
  used_gb: 0,
  balance_yuan: 0,
  max_rules: 20,
  speed_mbps: 100,
  monthly_reset: false,
  expire_at: '',
})

function formatDateInput(iso?: string): string {
  if (!iso || iso.startsWith('0001-')) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  const yyyy = d.getFullYear()
  const mm = String(d.getMonth() + 1).padStart(2, '0')
  const dd = String(d.getDate()).padStart(2, '0')
  return `${yyyy}-${mm}-${dd}`
}

function formatDateDisplay(iso?: string): string {
  const s = formatDateInput(iso)
  return s || '-'
}

function isUserExpired(u?: User | null): boolean {
  if (!u || u.role === 'admin' || !u.expire_at || u.expire_at.startsWith('0001-')) return false
  const d = new Date(u.expire_at)
  if (Number.isNaN(d.getTime())) return false
  return d.getTime() < Date.now()
}

function onUserPlanChange() {
  const p = plans.value.find((x) => x.id === Number(userForm.value.plan_id))
  if (p) {
    if (p.role_group_id) userForm.value.role_group_id = p.role_group_id
    userForm.value.quota_gb = Math.round((p.quota_bytes || 0) / GB)
    userForm.value.max_rules = p.max_rules
    userForm.value.speed_mbps = p.speed_mbps
    userForm.value.monthly_reset = Boolean(p.monthly_reset)
  }
}

function openCreateUserModal() {
  if (!isAdmin.value) return
  editingUserId.value = null
  const defPlan = plans.value[0]
  const nextMonth = new Date(Date.now() + (defPlan?.duration_days || 30) * 86400000)
  userForm.value = {
    id: 0,
    email: '',
    password: '',
    role: 'user',
    plan_id: defPlan?.id || 1,
    role_group_id: defPlan?.role_group_id || siteConfig.value.default_role_group_id || rolesList.value[0]?.id || 1,
    quota_gb: defPlan ? Math.round(defPlan.quota_bytes / GB) : siteConfig.value.default_quota_gb || 20,
    used_gb: 0,
    balance_yuan: 0,
    max_rules: defPlan ? defPlan.max_rules : siteConfig.value.default_max_rules || 5,
    speed_mbps: defPlan ? defPlan.speed_mbps : siteConfig.value.default_speed_mbps || 100,
    monthly_reset: Boolean(defPlan?.monthly_reset),
    expire_at: formatDateInput(nextMonth.toISOString()),
  }
  showUserModal.value = true
}

function openEditUserModal(u: User) {
  if (!isAdmin.value) return
  editingUserId.value = u.id
  userForm.value = {
    id: u.id,
    email: u.email,
    password: '',
    role: u.role,
    plan_id: u.plan_id || 0,
    role_group_id: u.role_group_id || rolesList.value[0]?.id || 1,
    quota_gb: Math.round(u.quota_bytes / GB),
    used_gb: Number(((u.used_bytes || 0) / GB).toFixed(1)),
    balance_yuan: Number(((u.balance_cents || 0) / 100).toFixed(2)),
    max_rules: u.max_rules,
    speed_mbps: u.speed_mbps,
    monthly_reset: Boolean(u.monthly_reset),
    expire_at: formatDateInput(u.expire_at),
  }
  showUserModal.value = true
}

async function submitUserEdit() {
  if (!isAdmin.value) return
  const rg = getRoleById(userForm.value.role_group_id)
  const allowedStr = userForm.value.role === 'admin' ? '*' : rg ? rg.allowed_tunnels : ''
  try {
    if (editingUserId.value) {
      await api.adminUpdateUser(userForm.value.id, {
        role: userForm.value.role,
        plan_id: Number(userForm.value.plan_id) || 0,
        role_group_id: Number(userForm.value.role_group_id) || 1,
        quota_bytes: Math.max(0, Number(userForm.value.quota_gb) || 0) * GB,
        used_bytes: Math.round(Math.max(0, Number(userForm.value.used_gb) || 0) * GB),
        balance_cents: Math.round(Math.max(0, Number(userForm.value.balance_yuan) || 0) * 100),
        max_rules: userForm.value.max_rules,
        speed_mbps: userForm.value.speed_mbps,
        monthly_reset: Boolean(userForm.value.monthly_reset),
        allowed_tunnels: allowedStr,
        expire_at: userForm.value.expire_at ? userForm.value.expire_at.trim() : undefined,
        password: userForm.value.password || undefined,
      })
      showToast('用户的套餐、角色、配额与到期时间已保存')
    } else {
      if (!userForm.value.email || !userForm.value.password) {
        showToast('请填写账号邮箱与登录密码')
        return
      }
      await api.adminCreateUser({
        email: userForm.value.email,
        password: userForm.value.password,
        role: userForm.value.role,
        plan_id: Number(userForm.value.plan_id) || 0,
        role_group_id: Number(userForm.value.role_group_id) || 1,
        quota_bytes: Math.max(0, Number(userForm.value.quota_gb) || 0) * GB,
        max_rules: userForm.value.max_rules,
        speed_mbps: userForm.value.speed_mbps,
        monthly_reset: Boolean(userForm.value.monthly_reset),
        allowed_tunnels: allowedStr,
        expire_at: userForm.value.expire_at ? userForm.value.expire_at.trim() : undefined,
      })
      showToast('新增用户成功')
    }
    showUserModal.value = false
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

async function resetUserTraffic(u: User) {
  if (!isAdmin.value) return
  try {
    await api.adminResetUserTraffic(u.id)
    showToast(`已重置 ${u.email} 的已用流量`)
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

async function resetUserSubscriptionAdmin(u: User) {
  if (!isAdmin.value) return
  if (
    !window.confirm(
      `确定重置用户 ${u.email} 的订阅吗？\n这将清零已用流量、按绑定套餐刷新到期时间与配额，并自动恢复因流量超额暂停的转发规则。`,
    )
  ) {
    return
  }
  try {
    await api.adminResetUserSubscription(u.id)
    showToast(`已重置 ${u.email} 的订阅周期与已用流量`)
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

async function resetUserSubTokenAdmin(u: User) {
  if (!isAdmin.value) return
  if (!window.confirm(`确定重置用户 ${u.email} 的订阅链接吗？重置后旧订阅链接将立即失效。`)) {
    return
  }
  try {
    const res = await api.adminResetUserSubToken(u.id)
    u.sub_token = res.sub_token
    if (user.value && user.value.id === u.id) {
      user.value.sub_token = res.sub_token
    }
    showToast(`已重置 ${u.email} 的订阅链接`)
  } catch (e: any) {
    showToast(e.message)
  }
}

// 管理员重置用户密码弹窗
const showAdminResetPwdModal = ref(false)
const adminResetPwdTarget = ref<User | null>(null)
const adminResetPwdInput = ref('')
const adminResetPwdResult = ref('')
const adminResetPwdError = ref('')

function openAdminResetPwdModal(u: User) {
  if (!isAdmin.value) return
  adminResetPwdTarget.value = u
  adminResetPwdInput.value = ''
  adminResetPwdResult.value = ''
  adminResetPwdError.value = ''
  showAdminResetPwdModal.value = true
}

async function submitAdminResetPwd(randomGenerate = false) {
  if (!isAdmin.value || !adminResetPwdTarget.value) return
  adminResetPwdError.value = ''
  const customPw = randomGenerate ? '' : adminResetPwdInput.value.trim()
  if (!randomGenerate && (customPw.length < 8 || customPw.length > 72)) {
    adminResetPwdError.value = '自定义新密码长度需为 8-72 位，或直接点击「随机生成并重置」'
    return
  }
  try {
    const res = await api.adminResetUserPassword(adminResetPwdTarget.value.id, customPw)
    if (res.token && user.value?.id === adminResetPwdTarget.value.id) {
      localStorage.setItem('nexus_token', res.token)
      token.value = res.token
    }
    adminResetPwdResult.value = res.password
    adminResetPwdInput.value = ''
    try {
      await navigator.clipboard.writeText(res.password)
      showToast('密码已重置并复制到剪贴板，该用户旧登录会话已失效')
    } catch {
      showToast(res.message || '密码已重置')
    }
  } catch (e: any) {
    adminResetPwdError.value = e.message || '重置密码失败'
  }
}

async function toggleUserBan(u: User) {
  if (!isAdmin.value) return
  try {
    const nextStatus = u.status === 'active' ? 'banned' : 'active'
    await api.adminUpdateUser(u.id, { status: nextStatus })
    showToast(nextStatus === 'banned' ? `已封禁 ${u.email}` : `已解封 ${u.email}`)
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

async function deleteUserAccount(u: User) {
  if (!isAdmin.value || u.role === 'admin') return
  try {
    await api.adminDeleteUser(u.id)
    showToast(`已删除用户 ${u.email}`)
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

// --- 系统设置 (管理员) ---
const settingsForm = ref({
  site_name: 'Zachary Panel',
  site_logo: 'ZP',
  announcement: '',
  allow_register: false,
  default_quota_gb: 20,
  default_max_rules: 5,
  default_speed_mbps: 100,
  default_role_group_id: 1,
  payment_enabled: false,
  epay_url: '',
  epay_pid: '',
  epay_key: '',
  usdt_address: '',
  usdt_webhook_secret: '',
  recharge_notice: '',
  notify_telegram_bot_token: '',
  notify_telegram_chat_id: '',
  notify_webhook_url: '',
  notify_on_node_events: false,
  notify_on_quota_events: false,
  notify_on_ticket_events: false,
  affiliate_enabled: true,
  affiliate_commission_rate: 10,
  affiliate_min_withdraw_yuan: 10,
  offpeak_enabled: false,
  offpeak_start: '00:00',
  offpeak_end: '08:00',
  offpeak_multiplier: 0.5,
  offpeak_timezone: 'Asia/Shanghai',
})

function syncSettingsForm() {
  settingsForm.value = {
    site_name: siteConfig.value.site_name,
    site_logo: siteConfig.value.site_logo,
    announcement: siteConfig.value.announcement,
    allow_register: siteConfig.value.allow_register,
    default_quota_gb: siteConfig.value.default_quota_gb ?? 20,
    default_max_rules: siteConfig.value.default_max_rules ?? 5,
    default_speed_mbps: siteConfig.value.default_speed_mbps ?? 100,
    default_role_group_id: siteConfig.value.default_role_group_id || rolesList.value[0]?.id || 1,
    payment_enabled: !!siteConfig.value.payment_enabled,
    epay_url: siteConfig.value.epay_url || '',
    epay_pid: siteConfig.value.epay_pid || '',
    epay_key: siteConfig.value.epay_key || '',
    usdt_address: siteConfig.value.usdt_address || '',
    usdt_webhook_secret: siteConfig.value.usdt_webhook_secret || '',
    recharge_notice: siteConfig.value.recharge_notice || '',
    notify_telegram_bot_token: siteConfig.value.notify_telegram_bot_token || '',
    notify_telegram_chat_id: siteConfig.value.notify_telegram_chat_id || '',
    notify_webhook_url: siteConfig.value.notify_webhook_url || '',
    notify_on_node_events: !!siteConfig.value.notify_on_node_events,
    notify_on_quota_events: !!siteConfig.value.notify_on_quota_events,
    notify_on_ticket_events: !!siteConfig.value.notify_on_ticket_events,
    affiliate_enabled: siteConfig.value.affiliate_enabled ?? true,
    affiliate_commission_rate: siteConfig.value.affiliate_commission_rate ?? 10,
    affiliate_min_withdraw_yuan: Number(((siteConfig.value.affiliate_min_withdraw_cents ?? 1000) / 100).toFixed(2)),
    offpeak_enabled: !!siteConfig.value.offpeak_enabled,
    offpeak_start: siteConfig.value.offpeak_start || '00:00',
    offpeak_end: siteConfig.value.offpeak_end || '08:00',
    offpeak_multiplier: siteConfig.value.offpeak_multiplier ?? 0.5,
    offpeak_timezone: siteConfig.value.offpeak_timezone || 'Asia/Shanghai',
  }
}

async function saveSystemSettings() {
  if (!isAdmin.value) return
  const defRole = getRoleById(settingsForm.value.default_role_group_id)
  try {
    const updated = await api.adminUpdateSettings({
      site_name: settingsForm.value.site_name.trim() || 'Zachary Panel',
      site_logo: settingsForm.value.site_logo.trim() || 'ZP',
      announcement: settingsForm.value.announcement.trim(),
      allow_register: settingsForm.value.allow_register,
      default_quota_gb: Number(settingsForm.value.default_quota_gb) || 20,
      default_max_rules: Number(settingsForm.value.default_max_rules) || 5,
      default_speed_mbps: Number(settingsForm.value.default_speed_mbps) || 100,
      default_role_group_id: Number(settingsForm.value.default_role_group_id) || 1,
      default_tunnels: defRole ? defRole.allowed_tunnels : siteConfig.value.default_tunnels,
      payment_enabled: settingsForm.value.payment_enabled,
      epay_url: settingsForm.value.epay_url.trim(),
      epay_pid: settingsForm.value.epay_pid.trim(),
      epay_key: settingsForm.value.epay_key.trim(),
      usdt_address: settingsForm.value.usdt_address.trim(),
      usdt_webhook_secret: settingsForm.value.usdt_webhook_secret.trim(),
      recharge_notice: settingsForm.value.recharge_notice.trim(),
      notify_telegram_bot_token: settingsForm.value.notify_telegram_bot_token.trim(),
      notify_telegram_chat_id: settingsForm.value.notify_telegram_chat_id.trim(),
      notify_webhook_url: settingsForm.value.notify_webhook_url.trim(),
      notify_on_node_events: settingsForm.value.notify_on_node_events,
      notify_on_quota_events: settingsForm.value.notify_on_quota_events,
      notify_on_ticket_events: settingsForm.value.notify_on_ticket_events,
      affiliate_enabled: settingsForm.value.affiliate_enabled,
      affiliate_commission_rate: Math.max(0, Math.min(50, Number(settingsForm.value.affiliate_commission_rate) || 0)),
      affiliate_min_withdraw_cents: Math.round(Math.max(1, Number(settingsForm.value.affiliate_min_withdraw_yuan) || 10) * 100),
      offpeak_enabled: settingsForm.value.offpeak_enabled,
      offpeak_start: settingsForm.value.offpeak_start.trim() || '00:00',
      offpeak_end: settingsForm.value.offpeak_end.trim() || '08:00',
      offpeak_multiplier: Math.max(0, Number(settingsForm.value.offpeak_multiplier) || 0),
      offpeak_timezone: settingsForm.value.offpeak_timezone.trim() || 'Asia/Shanghai',
    })
    siteConfig.value = updated
    document.title = siteConfig.value.site_name
    showToast('面板基础、闲时倍率、支付、分销与告警配置已保存')
  } catch (e: any) {
    showToast(e.message)
  }
}

async function sendTestNotify() {
  if (!isAdmin.value) return
  await saveSystemSettings()
  try {
    const res = await api.adminTestNotify()
    showToast(res.message || '测试通知已发送')
  } catch (e: any) {
    showToast(e.message)
  }
}

const auditFilterAction = ref('all')
const auditSearchQuery = ref('')
const debouncedAuditSearch = useDebouncedRef(auditSearchQuery, 220)
const auditPage = ref(1)
const auditPageSize = ref(20)

const filteredAuditLogs = computed(() => {
  const q = debouncedAuditSearch.value.trim().toLowerCase()
  return auditLogsList.value.filter((item) => {
    if (auditFilterAction.value !== 'all' && item.action !== auditFilterAction.value) return false
    if (q) {
      const hay = `${item.user_email || ''} ${item.action || ''} ${item.target || ''} ${item.detail || ''} ${item.client_ip || item.ip || ''}`.toLowerCase()
      if (!hay.includes(q)) return false
    }
    return true
  })
})

const auditTotalPages = computed(() => Math.max(1, Math.ceil(filteredAuditLogs.value.length / auditPageSize.value)))
const pagedAuditLogs = computed(() => {
  const p = Math.min(auditPage.value, auditTotalPages.value)
  const start = (p - 1) * auditPageSize.value
  return filteredAuditLogs.value.slice(start, start + auditPageSize.value)
})
watch([debouncedAuditSearch, auditFilterAction, auditPageSize], () => {
  auditPage.value = 1
})

async function refreshAuditLogs() {
  if (!isAdmin.value) return
  try {
    auditLogsList.value = await api.adminListAuditLogs()
  } catch (e: any) {
    showToast(e.message)
  }
}

async function downloadSQLiteBackup() {
  if (!isAdmin.value) return
  try {
    const filename = await api.adminDownloadSQLiteBackup()
    showToast(`已生成并下载 SQLite 热备快照 ${filename}`)
    await refreshAuditLogs()
  } catch (e: any) {
    showToast(e.message)
  }
}

const quotaPercent = computed(() => {
  if (!user.value || !user.value.quota_bytes) return 0
  return Math.min(100, Number(((user.value.used_bytes / user.value.quota_bytes) * 100).toFixed(1)))
})

// 修改密码与双因素认证 (2FA)
const showPasswordModal = ref(false)
const pwdForm = ref({ old: '', next: '', confirm: '' })
const pwdError = ref('')
const totpInput = ref('')
const totpRequired = ref(false)
const totpSetupData = ref<{ secret: string; otpauth_url: string } | null>(null)
const totpVerifyInput = ref('')
const totpDisableInput = ref('')
const generatedAdminAPIKey = ref('')

function openPasswordModal() {
  pwdForm.value = { old: '', next: '', confirm: '' }
  pwdError.value = ''
  totpSetupData.value = null
  totpVerifyInput.value = ''
  totpDisableInput.value = ''
  showPasswordModal.value = true
}

async function handleStartTOTPSetup() {
  try {
    totpSetupData.value = await api.setupTOTP()
    totpVerifyInput.value = ''
    showToast('已生成 2FA 密钥，请使用身份验证器扫描或输入密钥后填写 6 位验证码')
  } catch (e: any) {
    showToast(e.message)
  }
}

async function handleConfirmEnableTOTP() {
  if (!totpVerifyInput.value.trim()) {
    showToast('请输入身份验证器显示的 6 位动态验证码')
    return
  }
  try {
    const res = await api.enableTOTP(totpVerifyInput.value.trim())
    if (user.value) user.value.totp_enabled = true
    totpSetupData.value = null
    totpVerifyInput.value = ''
    showToast(res.message)
  } catch (e: any) {
    showToast(e.message)
  }
}

async function handleConfirmDisableTOTP() {
  if (!totpDisableInput.value.trim()) {
    showToast('请输入当前登录密码或 6 位 2FA 验证码以确认关闭')
    return
  }
  const v = totpDisableInput.value.trim()
  const payload = /^\d{6}$/.test(v) ? { code: v } : { password: v }
  try {
    const res = await api.disableTOTP(payload)
    if (user.value) user.value.totp_enabled = false
    totpDisableInput.value = ''
    totpSetupData.value = null
    showToast(res.message)
  } catch (e: any) {
    showToast(e.message)
  }
}

async function generateAdminAPIKey() {
  if (!isAdmin.value) return
  try {
    const res = await api.adminGenerateAPIKey()
    generatedAdminAPIKey.value = res.api_key
    siteConfig.value.admin_api_key_prefix = res.admin_api_key_prefix
    try {
      await navigator.clipboard.writeText(res.api_key)
      showToast('管理 API Key 已生成并复制到剪贴板')
    } catch {
      showToast(res.message)
    }
    await refreshAuditLogs()
  } catch (e: any) {
    showToast(e.message)
  }
}

async function revokeAdminAPIKey() {
  if (!isAdmin.value) return
  if (!window.confirm('确定吊销当前管理 API Key 吗？吊销后外部系统的调用将立即失效。')) {
    return
  }
  try {
    const res = await api.adminRevokeAPIKey()
    generatedAdminAPIKey.value = ''
    siteConfig.value.admin_api_key_prefix = ''
    showToast(res.message)
    await refreshAuditLogs()
  } catch (e: any) {
    showToast(e.message)
  }
}

async function submitChangePassword() {
  pwdError.value = ''
  if (pwdForm.value.next.length < 8 || pwdForm.value.next.length > 72) {
    pwdError.value = '新密码长度需为 8-72 位'
    return
  }
  if (pwdForm.value.next !== pwdForm.value.confirm) {
    pwdError.value = '两次输入的新密码不一致'
    return
  }
  try {
    const res = await api.changePassword(pwdForm.value.old, pwdForm.value.next)
    localStorage.setItem('nexus_token', res.token)
    token.value = res.token
    showPasswordModal.value = false
    showToast(res.message || '密码已修改')
  } catch (e: any) {
    pwdError.value = e.message || '修改失败'
  }
}

async function handleAuth() {
  authError.value = ''
  try {
    const res = isRegisterMode.value
      ? await api.register(emailInput.value.trim(), passwordInput.value, inviteCodeInput.value.trim())
      : await api.login(emailInput.value.trim(), passwordInput.value, totpInput.value.trim())
    passwordInput.value = ''
    totpInput.value = ''
    totpRequired.value = false
    isRegisterMode.value = false
    localStorage.setItem('nexus_token', res.token)
    token.value = res.token
    user.value = res.user
    if (res.user.role !== 'admin' && ['lines', 'nodes', 'roles', 'users', 'settings'].includes(activeTab.value)) {
      activeTab.value = 'dashboard'
    }
    await refreshAll()
  } catch (e: any) {
    if (e?.totp_required) {
      totpRequired.value = true
    }
    authError.value = e.message || (isRegisterMode.value ? '注册失败' : '登录失败')
  }
}

function logout() {
  localStorage.removeItem('nexus_token')
  token.value = null
  user.value = null
}

const hourlyStats = ref<Array<{ hour_bucket: string; upload_bytes: number; down_bytes: number; billed_bytes: number }>>([])
const globalHourlyStats = ref<Array<{ hour_bucket: string; upload_bytes: number; down_bytes: number; billed_bytes: number }>>([])
const chartViewScope = ref<'global' | 'personal'>('global')
const topUsers = ref<Array<{ id: number; email: string; used_bytes: number; quota_bytes: number; plan_id: number }>>([])
const topNodes = ref<Array<{ id: number; name: string; used_bytes: number; quota_bytes: number; status: string }>>([])

const activeHourlySeries = computed(() => {
  if (isAdmin.value && chartViewScope.value === 'global' && globalHourlyStats.value.length > 0) {
    return globalHourlyStats.value
  }
  return hourlyStats.value
})

const maxHourlyBilled = computed(() => {
  let max = 1
  for (const pt of activeHourlySeries.value) {
    const val = Math.max(pt.billed_bytes || 0, (pt.upload_bytes || 0) + (pt.down_bytes || 0))
    if (val > max) max = val
  }
  return max
})

const total24hBilled = computed(() =>
  activeHourlySeries.value.reduce((acc, pt) => acc + (pt.billed_bytes || 0), 0),
)

async function refreshAll() {
  try {
    const cfg = await api.getSiteConfig().catch(() => null)
    if (cfg) {
      siteConfig.value = cfg
      document.title = cfg.site_name || 'Zachary Panel'
      if (!cfg.allow_register) {
        isRegisterMode.value = false
      } else if (!token.value && inviteCodeInput.value) {
        isRegisterMode.value = true
      }
    }
  } catch {
    // ignore
  }
  if (!token.value) return
  try {
    const [dash, nodeList, lineList, planList, roleList, affOv] = await Promise.all([
      api.getDashboard(),
      api.getNodes(),
      api.getLines(),
      api.getPlans(),
      api.getRoles().catch(() => []),
      api.getAffiliateOverview().catch(() => null),
    ])
    user.value = dash.user
    hourlyStats.value = dash.hourly_stats || []
    globalHourlyStats.value = dash.global_hourly_stats || []
    topUsers.value = dash.top_users || []
    topNodes.value = dash.top_nodes || []
    nodes.value = nodeList
    lines.value = lineList
    plans.value = planList
    rolesList.value = roleList
    if (affOv) {
      affiliateOverview.value = affOv
    }
    if (dash.user.role === 'admin') {
      const [ruleList, uList, adminCfg, rcList, ordList, aLogs, cpList, wdList, tkList, foList] = await Promise.all([
        api.getRules({ all: true }),
        api.adminListUsers().catch(() => []),
        api.adminGetSettings().catch(() => null),
        api.adminListRedeemCodes().catch(() => []),
        api.getOrders({ all: true }).catch(() => []),
        api.adminListAuditLogs().catch(() => []),
        api.adminListCoupons().catch(() => []),
        api.adminListWithdrawals().catch(() => []),
        api.adminListTickets().catch(() => []),
        api.adminListDNSFailover().catch(() => []),
      ])
      rules.value = ruleList
      usersList.value = uList
      redeemCodesList.value = rcList
      ordersList.value = ordList
      auditLogsList.value = aLogs
      couponsList.value = cpList
      adminWithdrawalsList.value = wdList
      ticketsList.value = tkList
      dnsFailoverList.value = foList
      if (adminCfg) {
        siteConfig.value = adminCfg
        syncSettingsForm()
      }
    } else {
      const [ruleList, ordList, tkList] = await Promise.all([
        api.getRules(),
        api.getOrders().catch(() => []),
        api.listTickets().catch(() => []),
      ])
      rules.value = ruleList
      ordersList.value = ordList
      ticketsList.value = tkList
      if (['lines', 'nodes', 'roles', 'users', 'settings'].includes(activeTab.value)) {
        activeTab.value = 'dashboard'
      }
    }
  } catch (e: any) {
    if (String(e.message).includes('401')) logout()
  }
}

async function submitRule() {
  const targets: TargetEndpoint[] = ruleForm.value.targetsText
    .split('\n')
    .map((s) => parseTargetLine(s))
    .filter(Boolean) as TargetEndpoint[]

  const tun = getTunnelById(ruleForm.value.tunnel_line_id) || authorizedLines.value[0]
  if (!ruleForm.value.name || targets.length === 0 || !tun) {
    showToast('请填写完整信息')
    return
  }
  if (!userHasTunnel(user.value, tun.id)) {
    showToast('禁止越权使用未授权的隧道')
    return
  }

  const matchDomains = ruleForm.value.protocol === 'tcp' ? ruleForm.value.match_domains.trim() : ''
  const proxyProto = ruleForm.value.protocol === 'udp' ? 0 : Number(ruleForm.value.proxy_protocol || 0)
  const outboundIP = ruleForm.value.outbound_ip.trim()
  const ruleQuotaBytes = Math.round(Math.max(0, Number(ruleForm.value.rule_quota_gb) || 0) * GB)
  const dailyQuotaBytes = Math.round(Math.max(0, Number(ruleForm.value.daily_quota_gb) || 0) * GB)

  try {
    if (editingRuleId.value) {
      await api.updateRule(editingRuleId.value, {
        name: ruleForm.value.name,
        tunnel_line_id: tun.id,
        protocol: ruleForm.value.protocol,
        listen_port: Number(ruleForm.value.listen_port) || 0,
        load_balance: ruleForm.value.load_balance,
        targets,
        speed_mbps: Number(ruleForm.value.speed_mbps) || 0,
        access_mode: ruleForm.value.access_mode,
        access_cidrs: ruleForm.value.access_cidrs.trim(),
        match_domains: matchDomains,
        proxy_protocol: proxyProto,
        outbound_ip: outboundIP,
        rule_quota_bytes: ruleQuotaBytes,
        daily_quota_bytes: dailyQuotaBytes,
      })
      showToast('修改已保存')
    } else {
      await api.createRule({
        name: ruleForm.value.name,
        mode: tun.type === 'encrypt' ? 'tunnel' : 'direct',
        ingress_node_id: tun.ingress_node_id,
        tunnel_line_id: tun.id,
        engine: tun.engine,
        protocol: ruleForm.value.protocol,
        listen_port: Number(ruleForm.value.listen_port) || 0,
        load_balance: ruleForm.value.load_balance,
        targets,
        speed_mbps: Number(ruleForm.value.speed_mbps) || 0,
        access_mode: ruleForm.value.access_mode,
        access_cidrs: ruleForm.value.access_cidrs.trim(),
        match_domains: matchDomains,
        proxy_protocol: proxyProto,
        outbound_ip: outboundIP,
        rule_quota_bytes: ruleQuotaBytes,
        daily_quota_bytes: dailyQuotaBytes,
      })
      showToast('创建成功')
    }
    showRuleModal.value = false
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

async function handleToggleRule(rule: ForwardRule) {
  try {
    const updated = await api.toggleRule(rule.id)
    rule.enabled = updated.enabled
    rule.status = updated.status
  } catch (e: any) {
    showToast(e.message)
  }
}

async function handleProbeRule(rule: ForwardRule) {
  probingRuleId.value = rule.id
  try {
    const res = await api.probeRule(rule.id)
    probeResults.value[rule.id] = res
  } catch (e: any) {
    showToast(e.message)
  } finally {
    probingRuleId.value = null
  }
}

async function handleDeleteRule(id: number) {
  try {
    await api.deleteRule(id)
    rules.value = rules.value.filter((r) => r.id !== id)
    selectedRuleIds.value = selectedRuleIds.value.filter((rid) => rid !== id)
  } catch (e: any) {
    showToast(e.message)
  }
}

async function submitLine() {
  if (!isAdmin.value) return
  const f = lineForm.value
  const payload: Partial<TunnelLine> = {
    name: f.name.trim(),
    type: f.type,
    ingress_node_id: Number(f.ingress_node_id) || 0,
    hop_node_ids: f.type === 'encrypt' ? f.hop_node_ids.trim() : '',
    egress_node_id: f.type === 'encrypt' ? Number(f.egress_node_id) || 0 : 0,
    egress_node_ids: f.type === 'encrypt' ? f.egress_node_ids.trim() : '',
    load_balance: f.load_balance || 'round_robin',
    enable_mux: f.type === 'encrypt' && f.accel_mode === 'mux',
    enable_bonding: f.type === 'encrypt' && f.accel_mode === 'bonding',
    bond_links: Math.max(2, Math.min(8, Math.round(Number(f.bond_links) || 4))),
    proxy_protocol: Number(f.proxy_protocol || 0),
    offpeak_multiplier: Math.max(0, Number(f.offpeak_multiplier) || 0),
    transport: f.type === 'encrypt' ? f.transport : 'raw',
    engine: f.engine,
    billing_mode: f.billing_mode,
    rate_multiplier: Number(f.rate_multiplier) ?? 1,
    max_port_count: Number(f.max_port_count) ?? 50,
    port_range: f.port_range.trim(),
  }
  try {
    if (editingLineId.value) {
      await api.adminUpdateLine(editingLineId.value, payload)
      showToast('隧道已更新')
    } else {
      await api.adminCreateLine(payload)
      showToast('隧道已创建')
    }
    showLineModal.value = false
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

async function deleteLine(id: number) {
  if (!isAdmin.value) return
  try {
    await api.adminDeleteLine(id)
    lines.value = lines.value.filter((l) => l.id !== id)
  } catch (e: any) {
    showToast(e.message)
  }
}

async function submitNode() {
  if (!isAdmin.value) return
  const payload: Partial<NodeItem> = {
    name: nodeForm.value.name,
    connect_ip: nodeForm.value.connect_ip,
    server_ip: nodeForm.value.server_ip,
    outbound_ip: nodeForm.value.outbound_ip.trim(),
    allowed_outbound_ips: nodeForm.value.allowed_outbound_ips.trim(),
    port_range: nodeForm.value.port_range,
    traffic_rate: nodeForm.value.traffic_rate,
    quota_bytes: Math.max(0, Number(nodeForm.value.quota_gb) || 0) * GB,
    used_bytes: Math.max(0, Number(nodeForm.value.used_gb) || 0) * GB,
    reset_day: Math.min(28, Math.max(0, Number(nodeForm.value.reset_day) || 0)),
  }
  if (editingNodeId.value) {
    const curNode = nodeMap.value.get(editingNodeId.value)
    if (nodeForm.value.maintenance) {
      payload.status = 'maintenance'
    } else if (curNode?.status === 'maintenance') {
      payload.status = 'online'
    }
  }
  try {
    if (editingNodeId.value) {
      await api.adminUpdateNode(editingNodeId.value, payload)
      showToast('节点配置与流量已更新')
    } else {
      await api.adminCreateNode(payload)
      showToast('节点已添加')
    }
    showNodeModal.value = false
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

async function resyncNodeRules(node: NodeItem) {
  if (!isAdmin.value) return
  try {
    await api.adminResyncNode(node.id)
    showToast(`已重启并同步节点「${node.name}」的转发规则`)
  } catch (e: any) {
    showToast(e.message)
  }
}

async function resetNodeTraffic(node: NodeItem) {
  if (!isAdmin.value) return
  if (!window.confirm(`确定清零节点「${node.name}」的已用流量并恢复超额暂停规则吗？`)) {
    return
  }
  try {
    const res = await api.adminResetNodeTraffic(node.id)
    showToast(`节点已用流量已清零（已自动恢复 ${res.resumed_rules} 条规则）`)
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

async function deleteNode(id: number) {
  if (!isAdmin.value) return
  try {
    await api.adminDeleteNode(id)
    nodes.value = nodes.value.filter((n) => n.id !== id)
  } catch (e: any) {
    showToast(e.message)
  }
}

async function openInstallCmd(nodeId: number) {
  if (!isAdmin.value) return
  try {
    installInfo.value = await api.adminGetNodeInstallCmd(nodeId)
    showInstallModal.value = true
  } catch (e: any) {
    showToast(e.message)
  }
}

async function upgradeNodeRemote(node: NodeItem) {
  if (!isAdmin.value) return
  if (node.status !== 'online') {
    showToast(`节点「${node.name}」当前离线，无法远程升级`)
    return
  }
  try {
    const res = await api.adminUpgradeNode(node.id)
    showToast(res.message)
  } catch (e: any) {
    showToast(e.message)
  }
}

async function batchUpgradeOnlineNodes() {
  if (!isAdmin.value) return
  try {
    const res = await api.adminBatchUpgradeNodes()
    showToast(res.message)
  } catch (e: any) {
    showToast(e.message)
  }
}

const currentBoundPlan = computed<Plan | undefined>(() => {
  if (!user.value || !user.value.plan_id) return undefined
  return plans.value.find((p) => p.id === user.value?.plan_id)
})

function subscriptionUrlForToken(subToken?: string, query = ''): string {
  if (!subToken) return ''
  return `${window.location.origin}/api/v1/sub/${subToken}${query}`
}

const currentSubscriptionUrl = computed(() => subscriptionUrlForToken(user.value?.sub_token))

async function handleResetSubToken() {
  if (!window.confirm('确定重置您的订阅链接吗？重置后原有的订阅链接将立即失效。')) {
    return
  }
  try {
    const res = await api.resetSubToken()
    if (user.value) {
      user.value.sub_token = res.sub_token
    }
    showToast(res.message || '订阅链接已重置')
  } catch (e: any) {
    showToast(e.message)
  }
}

async function handleResetSubscription() {
  const p = currentBoundPlan.value
  if (!p) {
    showToast('当前账号未绑定套餐，请先在下方选购套餐')
    return
  }
  if (p.price_cents > 0) {
    openCheckoutModal('plan_reset', p)
    return
  }
  try {
    const res = await api.resetSubscription()
    user.value = res.user
    showToast(res.message)
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

async function handleRedeem() {
  if (!redeemInput.value.trim()) {
    showToast('请输入兑换码')
    return
  }
  try {
    const res = await api.redeemCode(redeemInput.value.trim())
    redeemInput.value = ''
    showToast(res.message)
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

// --- 管理员兑换码 / 卡密管理 ---
const showRedeemGenModal = ref(false)
const redeemFilterStatus = ref<'all' | 'unused' | 'used'>('all')
const redeemSearchKeyword = ref('')
const debouncedRedeemSearch = useDebouncedRef(redeemSearchKeyword, 220)
const redeemPage = ref(1)
const redeemPageSize = ref(20)
const lastGeneratedCodes = ref<string[]>([])
const redeemGenForm = ref({
  cardType: 'plan' as 'plan' | 'balance' | 'quota',
  count: 5,
  plan_id: 1,
  balance_yuan: 50,
  quota_gb: 100,
  duration_days: 30,
  prefix: 'ZP',
  note: '',
})

const filteredRedeemCodes = computed(() => {
  const kw = debouncedRedeemSearch.value.trim().toLowerCase()
  return redeemCodesList.value.filter((rc) => {
    if (redeemFilterStatus.value === 'unused' && rc.used_by > 0) return false
    if (redeemFilterStatus.value === 'used' && rc.used_by === 0) return false
    if (kw) {
      const hay = `${rc.code} ${rc.note || ''} ${rc.plan_name || ''} ${rc.used_by_email || ''}`.toLowerCase()
      if (!hay.includes(kw)) return false
    }
    return true
  })
})

const redeemTotalPages = computed(() => Math.max(1, Math.ceil(filteredRedeemCodes.value.length / redeemPageSize.value)))
const pagedRedeemCodes = computed(() => {
  const p = Math.min(redeemPage.value, redeemTotalPages.value)
  const start = (p - 1) * redeemPageSize.value
  return filteredRedeemCodes.value.slice(start, start + redeemPageSize.value)
})
watch([debouncedRedeemSearch, redeemFilterStatus, redeemPageSize], () => {
  redeemPage.value = 1
})

function openRedeemGenModal() {
  if (!isAdmin.value) return
  lastGeneratedCodes.value = []
  const defPlan = plans.value[0]
  redeemGenForm.value = {
    cardType: defPlan ? 'plan' : 'balance',
    count: 5,
    plan_id: defPlan?.id || 0,
    balance_yuan: 50,
    quota_gb: defPlan ? Math.round((defPlan.quota_bytes || 0) / GB) : 100,
    duration_days: defPlan ? defPlan.duration_days : 30,
    prefix: 'ZP',
    note: '',
  }
  showRedeemGenModal.value = true
}

function onRedeemGenPlanChange() {
  const p = plans.value.find((x) => x.id === Number(redeemGenForm.value.plan_id))
  if (p) {
    redeemGenForm.value.quota_gb = Math.round((p.quota_bytes || 0) / GB)
    redeemGenForm.value.duration_days = p.duration_days
  }
}

async function submitGenerateRedeemCodes() {
  if (!isAdmin.value) return
  const f = redeemGenForm.value
  const payload: {
    count: number
    plan_id?: number
    balance_cents?: number
    quota_gb?: number
    duration_days?: number
    prefix?: string
    note?: string
  } = {
    count: Math.min(100, Math.max(1, Number(f.count) || 5)),
    prefix: (f.prefix || 'ZP').trim(),
    note: (f.note || '').trim(),
  }

  if (f.cardType === 'plan') {
    payload.plan_id = Number(f.plan_id) || 0
    payload.quota_gb = Math.max(0, Number(f.quota_gb) || 0)
    payload.duration_days = Math.max(0, Number(f.duration_days) || 0)
  } else if (f.cardType === 'balance') {
    payload.balance_cents = Math.round(Math.max(0.01, Number(f.balance_yuan) || 0) * 100)
    payload.quota_gb = 0
    payload.duration_days = 0
  } else {
    payload.quota_gb = Math.max(1, Number(f.quota_gb) || 100)
    payload.duration_days = Math.max(0, Number(f.duration_days) || 30)
  }

  try {
    const created = await api.adminGenerateRedeemCodes(payload)
    lastGeneratedCodes.value = created.map((c) => c.code)
    redeemCodesList.value = [...created, ...redeemCodesList.value]
    try {
      await navigator.clipboard.writeText(lastGeneratedCodes.value.join('\n'))
      showToast(`已生成 ${created.length} 张卡密并自动复制到剪贴板`)
    } catch {
      showToast(`已生成 ${created.length} 张卡密`)
    }
  } catch (e: any) {
    showToast(e.message)
  }
}

async function copyAllUnusedRedeemCodes() {
  const unused = filteredRedeemCodes.value
    .filter((rc) => rc.used_by === 0)
    .map((rc) => sanitizeExportField(rc.code, 64))
    .filter(Boolean)
  if (unused.length === 0) {
    showToast('当前列表没有未使用的卡密')
    return
  }
  await copyConnectAddr(unused.join('\n'))
  showToast(`已安全复制 ${unused.length} 张未使用卡密`)
}

async function deleteRedeemCodeItem(rc: RedeemCodeItem) {
  if (!isAdmin.value) return
  try {
    await api.adminDeleteRedeemCode(rc.id)
    redeemCodesList.value = redeemCodesList.value.filter((x) => x.id !== rc.id)
    showToast(`已删除卡密 ${rc.code}`)
  } catch (e: any) {
    showToast(e.message)
  }
}

async function clearUsedRedeemCodes() {
  if (!isAdmin.value) return
  const usedCount = redeemCodesList.value.filter((x) => x.used_by > 0).length
  if (usedCount === 0) {
    showToast('当前没有已核销的卡密')
    return
  }
  if (!window.confirm(`确定一键清理全部 ${usedCount} 条已核销卡密记录吗？`)) {
    return
  }
  try {
    const res = await api.adminBatchDeleteRedeemCodes({ mode: 'used' })
    redeemCodesList.value = redeemCodesList.value.filter((x) => x.used_by === 0)
    showToast(`已清理 ${res.deleted} 条已核销卡密`)
  } catch (e: any) {
    showToast(e.message)
  }
}

// --- 在线充值与账单明细 ---
const showRechargeModal = ref(false)
const lastCreatedOrder = ref<BillingOrder | null>(null)
const safeCreatedOrderPayUrl = computed(() => safeExternalUrl(lastCreatedOrder.value?.pay_url))
const orderSearchQuery = ref('')
const debouncedOrderSearch = useDebouncedRef(orderSearchQuery, 220)
const orderFilterStatus = ref<'all' | 'paid' | 'pending' | 'cancelled'>('all')
const ordersPage = ref(1)
const ordersPageSize = ref(20)

const filteredOrders = computed(() => {
  const q = debouncedOrderSearch.value.trim().toLowerCase()
  return ordersList.value.filter((ord) => {
    if (orderFilterStatus.value !== 'all' && ord.status !== orderFilterStatus.value) return false
    if (q) {
      const hay = `${ord.order_no} ${ord.user_email || ''} ${ord.plan_name || ''} ${ord.trade_no || ''}`.toLowerCase()
      if (!hay.includes(q)) return false
    }
    return true
  })
})

const ordersTotalPages = computed(() => Math.max(1, Math.ceil(filteredOrders.value.length / ordersPageSize.value)))
const pagedOrders = computed(() => {
  const p = Math.min(ordersPage.value, ordersTotalPages.value)
  const start = (p - 1) * ordersPageSize.value
  return filteredOrders.value.slice(start, start + ordersPageSize.value)
})
watch([debouncedOrderSearch, orderFilterStatus, ordersPageSize], () => {
  ordersPage.value = 1
})

const rechargeForm = ref({
  amount_yuan: 50,
  gateway: 'epay' as 'epay' | 'usdt' | 'manual',
  pay_type: 'alipay' as 'alipay' | 'wxpay' | 'qqpay' | 'usdt',
})

function openRechargeModal() {
  lastCreatedOrder.value = null
  const epayReady = !!siteConfig.value.epay_enabled || !!(siteConfig.value.payment_enabled && siteConfig.value.epay_url)
  rechargeForm.value = {
    amount_yuan: 50,
    gateway: epayReady ? 'epay' : siteConfig.value.usdt_address ? 'usdt' : 'manual',
    pay_type: 'alipay',
  }
  showRechargeModal.value = true
}

async function submitRechargeOrder() {
  const cents = Math.round(Math.max(1, Number(rechargeForm.value.amount_yuan) || 0) * 100)
  try {
    const order = await api.createRechargeOrder({
      amount_cents: cents,
      gateway: rechargeForm.value.gateway,
      pay_type: rechargeForm.value.pay_type,
    })
    lastCreatedOrder.value = order
    ordersList.value = [order, ...ordersList.value]
    const safeUrl = safeExternalUrl(order.pay_url)
    if (safeUrl) {
      window.open(safeUrl, '_blank', 'noopener,noreferrer')
      showToast('已生成充值订单并打开支付页面')
    } else if (order.pay_url) {
      showToast('支付跳转链接协议不安全，已拦截外部跳转')
    } else {
      showToast(`充值订单 ${order.order_no} 已创建，请按说明完成支付`)
    }
  } catch (e: any) {
    showToast(e.message)
  }
}

async function confirmOrderAdmin(ord: BillingOrder) {
  if (!isAdmin.value) return
  if (
    !window.confirm(
      `确定确认订单 ${ord.order_no} (${ord.user_email} 充值 ¥${(ord.amount_cents / 100).toFixed(2)}) 已收款并入账吗？`,
    )
  ) {
    return
  }
  try {
    const res = await api.adminConfirmOrder(ord.id)
    showToast(res.message)
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

function formatDateTimeDisplay(iso?: string): string {
  if (!iso || iso.startsWith('0001-')) return '-'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '-'
  const yyyy = d.getFullYear()
  const mm = String(d.getMonth() + 1).padStart(2, '0')
  const dd = String(d.getDate()).padStart(2, '0')
  const hh = String(d.getHours()).padStart(2, '0')
  const mi = String(d.getMinutes()).padStart(2, '0')
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}`
}

function orderTypeLabel(tp: string): string {
  switch (tp) {
    case 'recharge':
      return '余额充值'
    case 'plan_purchase':
      return '套餐购买'
    case 'plan_reset':
      return '重置周期'
    case 'redeem':
      return '卡密核销'
    case 'affiliate_transfer':
      return '佣金转余额'
    default:
      return tp
  }
}

// --- 商业增长闭环 1：套餐结算台 + 优惠券实时试算抵扣 & 管理员优惠券管理 ---
const showCheckoutModal = ref(false)
const checkoutScene = ref<'plan_purchase' | 'plan_reset'>('plan_purchase')
const checkoutPlan = ref<Plan | null>(null)
const checkoutCouponInput = ref('')
const checkoutCouponPreview = ref<CouponPreviewResp | null>(null)
const checkoutCouponError = ref('')
const checkoutPreviewLoading = ref(false)
const checkoutSubmitting = ref(false)

watch(checkoutCouponInput, (val) => {
  const norm = val.trim().toUpperCase()
  if (checkoutCouponPreview.value && checkoutCouponPreview.value.coupon_code !== norm) {
    checkoutCouponPreview.value = null
  }
  if (checkoutCouponError.value) {
    checkoutCouponError.value = ''
  }
})

const checkoutPayableCents = computed(() => {
  if (checkoutCouponPreview.value) return checkoutCouponPreview.value.payable_cents
  return checkoutPlan.value?.price_cents || 0
})

function openCheckoutModal(scene: 'plan_purchase' | 'plan_reset', plan: Plan) {
  checkoutScene.value = scene
  checkoutPlan.value = plan
  checkoutCouponInput.value = ''
  checkoutCouponPreview.value = null
  checkoutCouponError.value = ''
  checkoutPreviewLoading.value = false
  checkoutSubmitting.value = false
  showCheckoutModal.value = true
}

function clearCheckoutCoupon() {
  checkoutCouponInput.value = ''
  checkoutCouponPreview.value = null
  checkoutCouponError.value = ''
}

async function handlePreviewCheckoutCoupon() {
  if (!checkoutPlan.value) return
  const code = checkoutCouponInput.value.trim()
  if (!code) {
    checkoutCouponPreview.value = null
    checkoutCouponError.value = '请输入优惠券码后再点击试算'
    return
  }
  checkoutPreviewLoading.value = true
  checkoutCouponError.value = ''
  try {
    const res = await api.previewCoupon({
      code,
      plan_id: checkoutPlan.value.id,
      scene: checkoutScene.value,
    })
    checkoutCouponPreview.value = res
    checkoutCouponInput.value = res.coupon_code
  } catch (e: any) {
    checkoutCouponPreview.value = null
    checkoutCouponError.value = e.message || '优惠券试算失败'
  } finally {
    checkoutPreviewLoading.value = false
  }
}

async function confirmCheckoutPayment() {
  const plan = checkoutPlan.value
  if (!plan || checkoutSubmitting.value) return
  const typedCode = checkoutCouponInput.value.trim()
  if (typedCode && !checkoutCouponPreview.value) {
    await handlePreviewCheckoutCoupon()
    if (!checkoutCouponPreview.value) {
      return
    }
  }
  const appliedCode = checkoutCouponPreview.value?.coupon_code || undefined
  checkoutSubmitting.value = true
  try {
    const res =
      checkoutScene.value === 'plan_reset'
        ? await api.resetSubscription(appliedCode)
        : await api.purchasePlan(plan.id, appliedCode)
    user.value = res.user
    showCheckoutModal.value = false
    showToast(res.message)
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  } finally {
    checkoutSubmitting.value = false
  }
}

async function handleBuyPlan(planId: number) {
  const plan = plans.value.find((p) => p.id === planId)
  if (!plan) return
  if (plan.price_cents > 0) {
    openCheckoutModal('plan_purchase', plan)
    return
  }
  try {
    const res = await api.purchasePlan(planId)
    showToast(res.message)
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

const couponSearchQuery = ref('')
const debouncedCouponSearch = useDebouncedRef(couponSearchQuery, 220)
const couponsPage = ref(1)
const couponsPageSize = ref(20)

const filteredCoupons = computed(() => {
  const q = debouncedCouponSearch.value.trim().toLowerCase()
  if (!q) return couponsList.value
  return couponsList.value.filter((cp) => `${cp.code} ${cp.name}`.toLowerCase().includes(q))
})
const couponsTotalPages = computed(() => Math.max(1, Math.ceil(filteredCoupons.value.length / couponsPageSize.value)))
const pagedCoupons = computed(() => {
  const p = Math.min(couponsPage.value, couponsTotalPages.value)
  const start = (p - 1) * couponsPageSize.value
  return filteredCoupons.value.slice(start, start + couponsPageSize.value)
})
watch([debouncedCouponSearch, couponsPageSize], () => {
  couponsPage.value = 1
})

const showCouponModal = ref(false)
const editingCouponId = ref<number | null>(null)
const couponForm = ref({
  code: '',
  name: '',
  type: 'percent' as 'percent' | 'fixed',
  percent_value: 20,
  fixed_yuan: 10,
  min_spend_yuan: 0,
  max_discount_yuan: 0,
  allowedPlanIds: [] as number[],
  starts_at: '',
  ends_at: '',
  max_uses: 0,
  per_user_limit: 1,
  active: true,
})

function openCreateCouponModal() {
  if (!isAdmin.value) return
  editingCouponId.value = null
  couponForm.value = {
    code: '',
    name: '',
    type: 'percent',
    percent_value: 20,
    fixed_yuan: 10,
    min_spend_yuan: 0,
    max_discount_yuan: 0,
    allowedPlanIds: [],
    starts_at: '',
    ends_at: '',
    max_uses: 0,
    per_user_limit: 1,
    active: true,
  }
  showCouponModal.value = true
}

function openEditCouponModal(cp: CouponItem) {
  if (!isAdmin.value) return
  editingCouponId.value = cp.id
  couponForm.value = {
    code: cp.code,
    name: cp.name,
    type: cp.type,
    percent_value: cp.type === 'percent' ? cp.value : 20,
    fixed_yuan: cp.type === 'fixed' ? Number((cp.value / 100).toFixed(2)) : 10,
    min_spend_yuan: Number(((cp.min_spend_cents || 0) / 100).toFixed(2)),
    max_discount_yuan: Number(((cp.max_discount_cents || 0) / 100).toFixed(2)),
    allowedPlanIds: parseAllowedIds(cp.allowed_plan_ids),
    starts_at: formatDateInput(cp.starts_at),
    ends_at: formatDateInput(cp.ends_at),
    max_uses: cp.max_uses || 0,
    per_user_limit: cp.per_user_limit ?? 1,
    active: cp.active,
  }
  showCouponModal.value = true
}

async function submitCouponForm() {
  if (!isAdmin.value) return
  const f = couponForm.value
  if (!f.name.trim()) {
    showToast('请输入优惠券名称')
    return
  }
  const value =
    f.type === 'percent'
      ? Math.round(Number(f.percent_value) || 0)
      : Math.round(Math.max(0, Number(f.fixed_yuan) || 0) * 100)
  const payload = {
    code: f.code.trim() || undefined,
    name: f.name.trim(),
    type: f.type,
    value,
    min_spend_cents: Math.round(Math.max(0, Number(f.min_spend_yuan) || 0) * 100),
    max_discount_cents:
      f.type === 'percent' ? Math.round(Math.max(0, Number(f.max_discount_yuan) || 0) * 100) : 0,
    allowed_plan_ids: f.allowedPlanIds.join(','),
    starts_at: f.starts_at ? f.starts_at.trim() : '',
    ends_at: f.ends_at ? f.ends_at.trim() : '',
    max_uses: Math.max(0, Math.round(Number(f.max_uses) || 0)),
    per_user_limit: Math.max(0, Math.round(Number(f.per_user_limit) || 0)),
    active: Boolean(f.active),
  }
  try {
    if (editingCouponId.value) {
      await api.adminUpdateCoupon(editingCouponId.value, payload)
      showToast('优惠券配置已更新')
    } else {
      const created = await api.adminCreateCoupon(payload)
      showToast(`优惠券 ${created.code} 已创建`)
    }
    showCouponModal.value = false
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

async function toggleCouponActive(cp: CouponItem) {
  if (!isAdmin.value) return
  try {
    const updated = await api.adminUpdateCoupon(cp.id, {
      name: cp.name,
      type: cp.type,
      value: cp.value,
      min_spend_cents: cp.min_spend_cents,
      max_discount_cents: cp.max_discount_cents,
      allowed_plan_ids: cp.allowed_plan_ids,
      starts_at: cp.starts_at || '',
      ends_at: cp.ends_at || '',
      max_uses: cp.max_uses,
      per_user_limit: cp.per_user_limit,
      active: !cp.active,
    })
    cp.active = updated.active
    showToast(updated.active ? `优惠券 ${cp.code} 已启用` : `优惠券 ${cp.code} 已停用`)
  } catch (e: any) {
    showToast(e.message)
  }
}

async function deleteCouponItem(cp: CouponItem) {
  if (!isAdmin.value) return
  if (!window.confirm(`确定删除优惠券「${cp.name}」(${cp.code}) 吗？`)) return
  try {
    await api.adminDeleteCoupon(cp.id)
    couponsList.value = couponsList.value.filter((x) => x.id !== cp.id)
    showToast(`已删除优惠券 ${cp.code}`)
  } catch (e: any) {
    showToast(e.message)
  }
}

// --- 商业增长闭环 2：邀请返利 / 推广分销中心 ---
function affiliateSceneLabel(scene: string): string {
  switch (scene) {
    case 'recharge':
      return '受邀人充值'
    case 'plan_purchase':
      return '购买套餐'
    case 'plan_reset':
      return '周期重置'
    default:
      return scene
  }
}

function withdrawMethodLabel(method: string): string {
  switch (method) {
    case 'usdt':
      return 'USDT-TRC20'
    case 'alipay':
      return '支付宝'
    case 'wechat':
      return '微信收款'
    case 'bank':
      return '银行卡'
    default:
      return method.toUpperCase()
  }
}

async function handleTransferCommission() {
  const avail = affiliateOverview.value?.commission_balance_cents ?? user.value?.commission_balance_cents ?? 0
  if (avail <= 0) {
    showToast('当前暂无可划转的推广佣金')
    return
  }
  if (!window.confirm(`确定将全部可用推广佣金 ¥${(avail / 100).toFixed(2)} 一键划转至账户余额吗？`)) {
    return
  }
  try {
    const res = await api.transferAffiliateCommission(0)
    user.value = res.user
    showToast(res.message)
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

const showWithdrawModal = ref(false)
const withdrawForm = ref({
  amount_yuan: 50,
  method: 'usdt' as 'usdt' | 'alipay' | 'wechat' | 'bank',
  account: '',
  real_name: '',
})

function openWithdrawModal() {
  const avail = affiliateOverview.value?.commission_balance_cents ?? user.value?.commission_balance_cents ?? 0
  const minCents = affiliateOverview.value?.min_withdraw_cents ?? siteConfig.value.affiliate_min_withdraw_cents ?? 1000
  withdrawForm.value = {
    amount_yuan: Number((Math.max(minCents, avail) / 100).toFixed(2)),
    method: 'usdt',
    account: '',
    real_name: '',
  }
  showWithdrawModal.value = true
}

async function submitWithdrawRequest() {
  const amountCents = Math.round(Math.max(0, Number(withdrawForm.value.amount_yuan) || 0) * 100)
  if (amountCents <= 0) {
    showToast('请输入有效的提现金额')
    return
  }
  if (!withdrawForm.value.account.trim()) {
    showToast('请填写收款钱包地址或收款账号')
    return
  }
  try {
    const res = await api.requestAffiliateWithdraw({
      amount_cents: amountCents,
      method: withdrawForm.value.method,
      account: withdrawForm.value.account.trim(),
      real_name: withdrawForm.value.real_name.trim() || undefined,
    })
    user.value = res.user
    showWithdrawModal.value = false
    showToast(res.message)
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

const withdrawFilterStatus = ref<'all' | 'pending' | 'approved' | 'rejected'>('all')
const withdrawSearchQuery = ref('')
const debouncedWithdrawSearch = useDebouncedRef(withdrawSearchQuery, 220)

const filteredAdminWithdrawals = computed(() => {
  const q = debouncedWithdrawSearch.value.trim().toLowerCase()
  return adminWithdrawalsList.value.filter((wd) => {
    if (withdrawFilterStatus.value !== 'all' && wd.status !== withdrawFilterStatus.value) return false
    if (q) {
      const hay = `${wd.withdraw_no} ${wd.user_email} ${wd.account} ${wd.real_name || ''}`.toLowerCase()
      if (!hay.includes(q)) return false
    }
    return true
  })
})

async function reviewWithdrawalAdmin(wd: AffiliateWithdrawalItem, action: 'approve' | 'reject') {
  if (!isAdmin.value) return
  const label = action === 'approve' ? '确认已打款并通过审核' : '驳回申请并将冻结佣金原路退回用户佣金余额'
  const remark = window.prompt(`提现单 ${wd.withdraw_no} (¥${(wd.amount_cents / 100).toFixed(2)}) — ${label}\n请输入审核备注（可留空）：`, '')
  if (remark === null) return
  try {
    const res = await api.adminReviewWithdrawal(wd.id, { action, remark: remark.trim() })
    showToast(res.message)
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

// --- 商业增长闭环 3：工单客服中心 (Ticket) ---
const ticketFilterStatus = ref<'all' | 'open' | 'answered' | 'customer_reply' | 'closed'>('all')
const ticketFilterCategory = ref<'all' | 'network' | 'rule' | 'billing' | 'account' | 'general'>('all')
const ticketSearchQuery = ref('')
const debouncedTicketSearch = useDebouncedRef(ticketSearchQuery, 220)
const ticketsPage = ref(1)
const ticketsPageSize = ref(20)

const filteredTickets = computed(() => {
  const q = debouncedTicketSearch.value.trim().toLowerCase()
  return ticketsList.value.filter((tk) => {
    if (ticketFilterStatus.value !== 'all' && tk.status !== ticketFilterStatus.value) return false
    if (ticketFilterCategory.value !== 'all' && tk.category !== ticketFilterCategory.value) return false
    if (q) {
      const hay = `${tk.ticket_no} ${tk.subject} ${tk.user_email || ''} ${tk.rule_name || ''}`.toLowerCase()
      if (!hay.includes(q)) return false
    }
    return true
  })
})

const ticketsTotalPages = computed(() => Math.max(1, Math.ceil(filteredTickets.value.length / ticketsPageSize.value)))
const pagedTickets = computed(() => {
  const p = Math.min(ticketsPage.value, ticketsTotalPages.value)
  const start = (p - 1) * ticketsPageSize.value
  return filteredTickets.value.slice(start, start + ticketsPageSize.value)
})
watch([debouncedTicketSearch, ticketFilterStatus, ticketFilterCategory, ticketsPageSize], () => {
  ticketsPage.value = 1
})

const pendingTicketCount = computed(() => {
  if (isAdmin.value) {
    return ticketsList.value.filter((t) => t.status === 'open' || t.status === 'customer_reply').length
  }
  return ticketsList.value.filter((t) => t.status === 'answered').length
})

function ticketCategoryText(cat: string): string {
  switch (cat) {
    case 'network':
      return '线路与网络'
    case 'rule':
      return '转发规则'
    case 'billing':
      return '账单与支付'
    case 'account':
      return '账号与权限'
    default:
      return '综合咨询'
  }
}

function ticketPriorityText(prio: string): string {
  switch (prio) {
    case 'urgent':
      return '紧急'
    case 'high':
      return '高优'
    case 'low':
      return '低优'
    default:
      return '常规'
  }
}

function ticketPriorityBadge(prio: string): string {
  switch (prio) {
    case 'urgent':
      return 'badge-danger'
    case 'high':
      return 'badge-warning'
    case 'low':
      return 'badge-neutral'
    default:
      return 'badge-info'
  }
}

function ticketStatusText(st: string): string {
  switch (st) {
    case 'open':
      return '待受理'
    case 'answered':
      return '客服已回复'
    case 'customer_reply':
      return '用户追问中'
    case 'closed':
      return '已结单'
    default:
      return st
  }
}

function ticketStatusBadge(st: string): string {
  switch (st) {
    case 'open':
      return 'badge-warning'
    case 'answered':
      return 'badge-success'
    case 'customer_reply':
      return 'badge-primary'
    case 'closed':
      return 'badge-neutral'
    default:
      return 'badge-neutral'
  }
}

const showCreateTicketModal = ref(false)
const ticketCreateForm = ref({
  subject: '',
  category: 'network' as 'network' | 'rule' | 'billing' | 'account' | 'general',
  priority: 'normal' as 'low' | 'normal' | 'high' | 'urgent',
  rule_id: 0,
  message: '',
})

function openCreateTicketModal() {
  ticketCreateForm.value = {
    subject: '',
    category: 'network',
    priority: 'normal',
    rule_id: 0,
    message: '',
  }
  showCreateTicketModal.value = true
}

async function submitCreateTicket() {
  const f = ticketCreateForm.value
  if (!f.subject.trim() || !f.message.trim()) {
    showToast('请填写工单标题与详细问题描述')
    return
  }
  try {
    const res = await api.createTicket({
      subject: f.subject.trim(),
      category: f.category,
      priority: f.priority,
      rule_id: Number(f.rule_id) > 0 ? Number(f.rule_id) : undefined,
      message: f.message.trim(),
    })
    showCreateTicketModal.value = false
    ticketsList.value = [res.ticket, ...ticketsList.value]
    showToast(`工单 ${res.ticket.ticket_no} 已提交，客服将尽快响应`)
    activeTicket.value = res.ticket
    activeTicketMessages.value = res.messages || []
    ticketReplyInput.value = ''
    showTicketDetailModal.value = true
  } catch (e: any) {
    showToast(e.message)
  }
}

const showTicketDetailModal = ref(false)
const activeTicket = ref<SupportTicketItem | null>(null)
const activeTicketMessages = ref<TicketMessageItem[]>([])
const ticketReplyInput = ref('')
const ticketThreadRef = ref<HTMLElement | null>(null)

function scrollTicketThreadToBottom() {
  nextTick(() => {
    if (ticketThreadRef.value) {
      ticketThreadRef.value.scrollTop = ticketThreadRef.value.scrollHeight
    }
  })
}

async function openTicketDetail(tk: SupportTicketItem) {
  try {
    const res = await api.getTicketDetail(tk.id)
    activeTicket.value = res.ticket
    activeTicketMessages.value = res.messages || []
    ticketReplyInput.value = ''
    showTicketDetailModal.value = true
    scrollTicketThreadToBottom()
  } catch (e: any) {
    showToast(e.message)
  }
}

async function submitTicketReply() {
  if (!activeTicket.value) return
  const msg = ticketReplyInput.value.trim()
  if (!msg) {
    showToast('请输入回复内容')
    return
  }
  try {
    const res = await api.replyTicket(activeTicket.value.id, msg)
    activeTicket.value = res.ticket
    activeTicketMessages.value = [...activeTicketMessages.value, res.message]
    ticketReplyInput.value = ''
    const idx = ticketsList.value.findIndex((x) => x.id === res.ticket.id)
    if (idx >= 0) {
      ticketsList.value[idx] = res.ticket
    }
    scrollTicketThreadToBottom()
    showToast('回复已发送')
  } catch (e: any) {
    showToast(e.message)
  }
}

async function handleCloseActiveTicket(target?: SupportTicketItem) {
  const tk = target || activeTicket.value
  if (!tk) return
  if (!window.confirm(`确定关闭工单「${tk.subject}」(${tk.ticket_no}) 吗？`)) return
  try {
    const res = await api.closeTicket(tk.id)
    if (activeTicket.value?.id === tk.id) {
      activeTicket.value = res.ticket
    }
    const idx = ticketsList.value.findIndex((x) => x.id === tk.id)
    if (idx >= 0) {
      ticketsList.value[idx] = res.ticket
    }
    showToast(res.message || '工单已结单')
  } catch (e: any) {
    showToast(e.message)
  }
}

async function handleAdminTicketStatusChange(status: string, priority?: string) {
  if (!isAdmin.value || !activeTicket.value) return
  try {
    const res = await api.adminUpdateTicketStatus(activeTicket.value.id, { status, priority })
    activeTicket.value = res.ticket
    const idx = ticketsList.value.findIndex((x) => x.id === res.ticket.id)
    if (idx >= 0) {
      ticketsList.value[idx] = res.ticket
    }
    showToast(res.message)
  } catch (e: any) {
    showToast(e.message)
  }
}

function getTunnelById(id: number): TunnelLine | undefined {
  return lineMap.value.get(id)
}

// 规则实际运行引擎与配置引擎不同（限速规则从 gost/realm 回退到 native）
function ruleEngineFallback(rule: ForwardRule): boolean {
  return !!rule.effective_engine && rule.effective_engine !== (rule.engine || 'native')
}

function nodeNameById(id: number): string {
  return nodeMap.value.get(id)?.name || `#${id}`
}

function nodeConnectIPById(id: number): string {
  const n = nodeMap.value.get(id)
  return n ? n.connect_ip || n.public_host || n.server_ip : '127.0.0.1'
}

function userEmailById(uid: number): string {
  return userMap.value.get(uid)?.email || `#${uid}`
}

const targetsCache: Record<string, TargetEndpoint[]> = {}
function parseTargets(jsonStr: string): TargetEndpoint[] {
  if (targetsCache[jsonStr]) return targetsCache[jsonStr]
  try {
    const parsed = JSON.parse(jsonStr) || []
    targetsCache[jsonStr] = parsed
    return parsed
  } catch {
    return []
  }
}

// --- 全局 Ctrl / Cmd + K 快速检索与跳转面板 + Esc 快捷键关闭 ---
interface CommandItem {
  id: string
  category: string
  badgeClass?: string
  title: string
  subtitle?: string
  keywords: string
  run: () => void
}

const showCommandPalette = ref(false)
const cmdkQuery = ref('')
const cmdkActiveIndex = ref(0)
const cmdkInputRef = ref<HTMLInputElement | null>(null)

function openCommandPalette() {
  if (!token.value) return
  showCommandPalette.value = true
  cmdkQuery.value = ''
  cmdkActiveIndex.value = 0
  nextTick(() => {
    cmdkInputRef.value?.focus()
  })
}

const commandItems = computed<CommandItem[]>(() => {
  if (!token.value) return []
  const items: CommandItem[] = [
    {
      id: 'nav-dashboard',
      category: '导航',
      badgeClass: 'badge-primary',
      title: '前往 概览仪表盘',
      subtitle: '查看流量趋势、订阅链接与配额使用率',
      keywords: 'dashboard 概览 首页 监控 趋势 订阅',
      run: () => switchTab('dashboard'),
    },
    {
      id: 'nav-rules',
      category: '导航',
      badgeClass: 'badge-primary',
      title: '前往 转发管理',
      subtitle: `管理当前 ${visibleRules.value.length} 条端口与专线转发规则`,
      keywords: 'rules 转发 规则 端口 测速 导入 导出',
      run: () => switchTab('rules'),
    },
    {
      id: 'nav-store',
      category: '导航',
      badgeClass: 'badge-primary',
      title: '前往 套餐与账单中心',
      subtitle: '购买套餐、优惠券抵扣、充值余额、核销卡密与账单',
      keywords: 'store coupon 套餐 商城 优惠券 折扣码 充值 账单 订单 卡密 兑换码',
      run: () => switchTab('store'),
    },
    {
      id: 'nav-affiliate',
      category: '导航',
      badgeClass: 'badge-primary',
      title: '前往 推广返利中心',
      subtitle: '复制专属推广链接、查看返佣明细、一键划转余额或申请提现',
      keywords: 'affiliate invite referral 推广 邀请 返利 分销 佣金 提现',
      run: () => switchTab('affiliate'),
    },
    {
      id: 'nav-tickets',
      category: '导航',
      badgeClass: 'badge-primary',
      title: '前往 工单客服中心',
      subtitle: `提交技术与账单工单、对话追问（当前 ${ticketsList.value.length} 张工单）`,
      keywords: 'tickets support 工单 客服 售后 咨询 故障',
      run: () => switchTab('tickets'),
    },
    {
      id: 'act-create-rule',
      category: '操作',
      badgeClass: 'badge-success',
      title: '+ 新增转发规则',
      subtitle: '快速创建 TCP / UDP / 加密隧道转发规则',
      keywords: 'create add rule 新增 创建 转发 规则',
      run: () => {
        switchTab('rules')
        openCreateRuleModal()
      },
    },
    {
      id: 'act-batch-rule',
      category: '操作',
      badgeClass: 'badge-info',
      title: '批量导入转发规则',
      subtitle: '支持多行文本、CSV 或 JSON 批量创建规则',
      keywords: 'batch import 批量 导入 规则',
      run: () => {
        switchTab('rules')
        openBatchModal()
      },
    },
    {
      id: 'act-create-ticket',
      category: '操作',
      badgeClass: 'badge-info',
      title: '+ 提交客服工单',
      subtitle: '关联转发规则发起网络、账单或账号技术支持工单',
      keywords: 'ticket support create 提交 新建 工单 客服',
      run: () => {
        switchTab('tickets')
        openCreateTicketModal()
      },
    },
    {
      id: 'act-recharge',
      category: '操作',
      badgeClass: 'badge-success',
      title: '在线充值账户余额',
      subtitle: '支持易支付收银台 / USDT-TRC20 / 人工充值',
      keywords: 'recharge pay topup 充值 余额 支付 usdt epay',
      run: () => openRechargeModal(),
    },
    {
      id: 'act-security',
      category: '安全',
      badgeClass: 'badge-warning',
      title: '修改密码 / 配置双因素认证 (2FA)',
      subtitle: user.value?.totp_enabled ? '当前 2FA 已启用' : '绑定 Google / Microsoft Authenticator',
      keywords: 'password totp 2fa 安全 密码 双因素 认证',
      run: () => openPasswordModal(),
    },
    {
      id: 'act-theme',
      category: '界面',
      badgeClass: 'badge-neutral',
      title: isDark.value ? '切换至 浅色主题 (Light)' : '切换至 深色主题 (Dark)',
      subtitle: '即时切换并记住您的深浅色偏好',
      keywords: 'theme dark light 深色 浅色 夜间 主题 外观',
      run: () => toggleTheme(),
    },
  ]

  if (isAdmin.value) {
    items.push(
      {
        id: 'nav-lines',
        category: '管理',
        badgeClass: 'badge-purple',
        title: '前往 隧道管理',
        subtitle: `共 ${lines.value.length} 条端口直转与加密对接隧道`,
        keywords: 'lines tunnels 隧道 专线 线路',
        run: () => switchTab('lines'),
      },
      {
        id: 'nav-nodes',
        category: '管理',
        badgeClass: 'badge-purple',
        title: '前往 节点管理',
        subtitle: `共 ${nodes.value.length} 台转发节点服务器`,
        keywords: 'nodes servers 节点 服务器 探针 升级 对接',
        run: () => switchTab('nodes'),
      },
      {
        id: 'nav-roles',
        category: '管理',
        badgeClass: 'badge-purple',
        title: '前往 角色管理',
        subtitle: '配置角色权限组与授权可用隧道',
        keywords: 'roles groups 角色 权限组',
        run: () => switchTab('roles'),
      },
      {
        id: 'nav-users',
        category: '管理',
        badgeClass: 'badge-purple',
        title: '前往 用户管理',
        subtitle: `共 ${usersList.value.length} 位注册用户`,
        keywords: 'users tenants 用户 账号 配额 封禁',
        run: () => switchTab('users'),
      },
      {
        id: 'nav-settings',
        category: '管理',
        badgeClass: 'badge-purple',
        title: '前往 系统设置与审计日志',
        subtitle: '支付网关、分销返佣、告警通知、API Key、SQLite 热备与审计',
        keywords: 'settings audit backup 设置 分销 告警 支付 审计 备份 api key',
        run: () => switchTab('settings'),
      },
      {
        id: 'act-add-coupon',
        category: '操作',
        badgeClass: 'badge-success',
        title: '+ 新增优惠券 / 折扣码',
        subtitle: '创建百分比折扣券或固定满减券并限定适用套餐',
        keywords: 'coupon discount 优惠券 折扣码 满减 新增',
        run: () => {
          switchTab('store')
          openCreateCouponModal()
        },
      },
      {
        id: 'act-add-node',
        category: '操作',
        badgeClass: 'badge-success',
        title: '+ 新增转发节点',
        subtitle: '注册新节点并生成 Agent 对接脚本',
        keywords: 'add create node 新增 节点 服务器',
        run: () => {
          switchTab('nodes')
          openCreateNodeModal()
        },
      },
      {
        id: 'act-add-failover',
        category: '容灾',
        badgeClass: 'badge-info',
        title: '+ 新增多入口 DNS 自动容灾组',
        subtitle: '监控主备入口节点在线状态并自动切换 Cloudflare / DNSPod / Webhook 解析',
        keywords: 'dns failover ha cloudflare dnspod 容灾 主备 多入口 切换 解析',
        run: () => {
          switchTab('nodes')
          openCreateFailoverModal()
        },
      },
      {
        id: 'act-backup-db',
        category: '运维',
        badgeClass: 'badge-info',
        title: '一键导出 SQLite 热备快照 (.db)',
        subtitle: '在线一致性导出主控数据库文件',
        keywords: 'sqlite backup db 热备 备份 导出 数据库',
        run: () => downloadSQLiteBackup(),
      },
    )
  }

  for (const r of visibleRules.value.slice(0, 50)) {
    const addr = `${nodeConnectIPById(r.ingress_node_id)}:${r.listen_port}`
    items.push({
      id: `rule-${r.id}`,
      category: '规则',
      badgeClass: ruleStatusBadge(r),
      title: `${r.name} (${addr})`,
      subtitle: `${r.protocol.toUpperCase()} · ${getTunnelById(r.tunnel_line_id)?.name || '直连'}${r.match_domains ? ' · SNI:' + r.match_domains : ''}`,
      keywords: `${r.name} ${r.listen_port} ${r.targets_json} ${r.match_domains || ''} ${r.outbound_ip || ''} ${addr}`,
      run: () => {
        switchTab('rules')
        ruleSearchQuery.value = String(r.listen_port || r.name)
      },
    })
  }

  for (const tk of ticketsList.value.slice(0, 20)) {
    items.push({
      id: `ticket-${tk.id}`,
      category: '工单',
      badgeClass: ticketStatusBadge(tk.status),
      title: `${tk.ticket_no} · ${tk.subject}`,
      subtitle: `${ticketStatusText(tk.status)} · ${tk.user_email}`,
      keywords: `${tk.ticket_no} ${tk.subject} ${tk.user_email}`,
      run: () => {
        switchTab('tickets')
        openTicketDetail(tk)
      },
    })
  }

  if (isAdmin.value) {
    for (const fg of dnsFailoverList.value.slice(0, 20)) {
      items.push({
        id: `failover-${fg.id}`,
        category: '容灾',
        badgeClass: fg.enabled ? 'badge-success' : 'badge-neutral',
        title: `${fg.name} (${fg.domain})`,
        subtitle: `${fg.provider.toUpperCase()} · 当前生效: ${fg.active_node_id ? nodeNameById(fg.active_node_id) : '待同步'}`,
        keywords: `dns failover ${fg.name} ${fg.domain} ${fg.provider} 容灾`,
        run: () => {
          switchTab('nodes')
          openEditFailoverModal(fg)
        },
      })
    }
    for (const n of nodes.value.slice(0, 30)) {
      items.push({
        id: `node-${n.id}`,
        category: '节点',
        badgeClass: n.status === 'online' ? 'badge-success' : n.status === 'maintenance' ? 'badge-warning' : 'badge-danger',
        title: n.name,
        subtitle: `${n.connect_ip || n.server_ip} · ${n.status === 'online' ? '在线' : n.status === 'maintenance' ? '维护中' : '离线'}`,
        keywords: `${n.name} ${n.connect_ip} ${n.server_ip}`,
        run: () => {
          switchTab('nodes')
          openEditNodeModal(n)
        },
      })
    }
    for (const u of usersList.value.slice(0, 40)) {
      items.push({
        id: `user-${u.id}`,
        category: '用户',
        badgeClass: 'badge-info',
        title: u.email,
        subtitle: `#${u.id} · ${planNameById(u.plan_id)}`,
        keywords: `${u.email} ${u.id}`,
        run: () => {
          switchTab('users')
          userSearchQuery.value = u.email
        },
      })
    }
  }

  return items
})

const filteredCommandItems = computed(() => {
  const q = cmdkQuery.value.trim().toLowerCase()
  if (!q) {
    return commandItems.value.slice(0, 14)
  }
  const tokens = q.split(/\s+/).filter(Boolean)
  return commandItems.value
    .filter((item) => {
      const hay = `${item.category} ${item.title} ${item.subtitle || ''} ${item.keywords}`.toLowerCase()
      return tokens.every((tk) => hay.includes(tk))
    })
    .slice(0, 20)
})

watch(cmdkQuery, () => {
  cmdkActiveIndex.value = 0
})

function moveCmdkSelection(delta: number) {
  const len = filteredCommandItems.value.length
  if (len === 0) return
  cmdkActiveIndex.value = (cmdkActiveIndex.value + delta + len) % len
}

function runCommandItem(item: CommandItem) {
  showCommandPalette.value = false
  item.run()
}

function executeCmdkSelection() {
  const item = filteredCommandItems.value[cmdkActiveIndex.value]
  if (item) {
    runCommandItem(item)
  }
}

function isAnyModalOpen(): boolean {
  return (
    showCommandPalette.value ||
    showFailoverModal.value ||
    showTicketDetailModal.value ||
    showCreateTicketModal.value ||
    showWithdrawModal.value ||
    showCouponModal.value ||
    showCheckoutModal.value ||
    showRuleModal.value ||
    showLineModal.value ||
    showNodeModal.value ||
    showInstallModal.value ||
    showBatchModal.value ||
    showRoleModal.value ||
    showPlanModal.value ||
    showUserModal.value ||
    showPasswordModal.value ||
    showAdminResetPwdModal.value ||
    showRedeemGenModal.value ||
    showRechargeModal.value
  )
}

function closeTopModal(): boolean {
  if (showCommandPalette.value) {
    showCommandPalette.value = false
    return true
  }
  if (showFailoverModal.value) {
    showFailoverModal.value = false
    return true
  }
  if (showTicketDetailModal.value) {
    showTicketDetailModal.value = false
    return true
  }
  if (showCreateTicketModal.value) {
    showCreateTicketModal.value = false
    return true
  }
  if (showWithdrawModal.value) {
    showWithdrawModal.value = false
    return true
  }
  if (showCouponModal.value) {
    showCouponModal.value = false
    return true
  }
  if (showCheckoutModal.value) {
    showCheckoutModal.value = false
    return true
  }
  if (showRechargeModal.value) {
    showRechargeModal.value = false
    return true
  }
  if (showRedeemGenModal.value) {
    showRedeemGenModal.value = false
    return true
  }
  if (showAdminResetPwdModal.value) {
    showAdminResetPwdModal.value = false
    return true
  }
  if (showPasswordModal.value) {
    showPasswordModal.value = false
    return true
  }
  if (showUserModal.value) {
    showUserModal.value = false
    return true
  }
  if (showPlanModal.value) {
    showPlanModal.value = false
    return true
  }
  if (showRoleModal.value) {
    showRoleModal.value = false
    return true
  }
  if (showBatchModal.value) {
    showBatchModal.value = false
    return true
  }
  if (showInstallModal.value) {
    showInstallModal.value = false
    return true
  }
  if (showNodeModal.value) {
    showNodeModal.value = false
    return true
  }
  if (showLineModal.value) {
    showLineModal.value = false
    return true
  }
  if (showRuleModal.value) {
    showRuleModal.value = false
    return true
  }
  if (showMobileNav.value) {
    showMobileNav.value = false
    return true
  }
  return false
}

function handleGlobalKeydown(e: KeyboardEvent) {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
    if (token.value) {
      e.preventDefault()
      if (showCommandPalette.value) {
        showCommandPalette.value = false
      } else {
        openCommandPalette()
      }
    }
    return
  }
  if (e.key === 'Escape') {
    if (closeTopModal()) {
      e.preventDefault()
    }
  }
}

const isPageVisible = ref(typeof document === 'undefined' ? true : !document.hidden)
let telemetryInFlight = false
async function pollTelemetryRealtime() {
  if (!autoRefresh.value || !token.value || document.hidden || isAnyModalOpen() || telemetryInFlight) {
    return
  }
  telemetryInFlight = true
  try {
    const t = await api.getTelemetry()
    if (user.value && t.user) {
      user.value.used_bytes = t.user.used_bytes
      user.value.quota_bytes = t.user.quota_bytes
      user.value.status = t.user.status
      if (t.user.balance_cents !== undefined) user.value.balance_cents = t.user.balance_cents
      if (t.user.commission_balance_cents !== undefined) {
        user.value.commission_balance_cents = t.user.commission_balance_cents
      }
      if (t.user.expire_at !== undefined) user.value.expire_at = t.user.expire_at
      if (t.user.max_rules !== undefined) user.value.max_rules = t.user.max_rules
      if (t.user.speed_mbps !== undefined) user.value.speed_mbps = t.user.speed_mbps
      if (t.user.plan_id !== undefined) user.value.plan_id = t.user.plan_id
      if (t.user.role_group_id !== undefined) user.value.role_group_id = t.user.role_group_id
      if (t.user.allowed_tunnels !== undefined) user.value.allowed_tunnels = t.user.allowed_tunnels
    }
    if (Array.isArray(t.nodes)) {
      const nMap = nodeMap.value
      for (const nd of t.nodes) {
        if (!nd.id) continue
        const target = nMap.get(nd.id)
        if (target) {
          Object.assign(target, nd)
        }
      }
    }
    if (Array.isArray(t.rules)) {
      const rMap = new Map(rules.value.map((r) => [r.id, r]))
      for (const rd of t.rules) {
        const target = rMap.get(rd.id)
        if (target) {
          target.upload_bytes = rd.upload_bytes
          target.down_bytes = rd.down_bytes
          target.billed_bytes = rd.billed_bytes
          if (rd.daily_used_bytes !== undefined) target.daily_used_bytes = rd.daily_used_bytes
          if (rd.daily_reset_date !== undefined) target.daily_reset_date = rd.daily_reset_date
          if (rd.rule_quota_bytes !== undefined) target.rule_quota_bytes = rd.rule_quota_bytes
          if (rd.daily_quota_bytes !== undefined) target.daily_quota_bytes = rd.daily_quota_bytes
          target.enabled = rd.enabled
          target.status = rd.status
        }
      }
    }
  } catch {
    // 忽略瞬时网络抖动，不弹窗打扰用户
  } finally {
    telemetryInFlight = false
  }
}

let telemetryTimer: ReturnType<typeof setInterval> | null = null
function handleVisibilityChange() {
  isPageVisible.value = !document.hidden
  if (!document.hidden && autoRefresh.value && token.value) {
    pollTelemetryRealtime()
  }
}

function handleUnauthorized() {
  logout()
  showToast('登录已失效，请重新登录')
}

onMounted(() => {
  try {
    const params = new URLSearchParams(window.location.search)
    const refCode = (params.get('ref') || params.get('invite') || params.get('aff') || '').trim()
    if (refCode) {
      inviteCodeInput.value = refCode.slice(0, 32).toUpperCase()
    }
  } catch {
    // ignore URL parse errors
  }
  window.addEventListener('nexus-unauthorized', handleUnauthorized)
  window.addEventListener('keydown', handleGlobalKeydown)
  refreshAll()
  telemetryTimer = setInterval(pollTelemetryRealtime, 3000)
  document.addEventListener('visibilitychange', handleVisibilityChange)
})

onUnmounted(() => {
  window.removeEventListener('nexus-unauthorized', handleUnauthorized)
  window.removeEventListener('keydown', handleGlobalKeydown)
  if (telemetryTimer) clearInterval(telemetryTimer)
  document.removeEventListener('visibilitychange', handleVisibilityChange)
})
</script>

<template>
  <div>
    <div v-if="toastMsg" class="toast">{{ toastMsg }}</div>

    <!-- 登录 / 注册页 -->
    <div
      v-if="!token"
      style="min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 16px;"
    >
      <div class="card" style="width: 100%; max-width: 400px; padding: 28px;">
        <div style="display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 20px;">
          <div style="display: flex; align-items: center; gap: 11px; min-width: 0;">
            <div class="brand-logo">{{ siteConfig.site_logo || 'ZP' }}</div>
            <div>
              <h1 style="font-size: 16.5px; font-weight: 700; line-height: 1.25;">{{ siteConfig.site_name || 'Zachary Panel' }}</h1>
              <div style="font-size: 11.5px; color: var(--text-muted); margin-top: 2px;">分布式多引擎流量转发控制台</div>
            </div>
          </div>
          <button type="button" @click="toggleTheme" class="btn btn-outline btn-sm" :title="isDark ? '切换浅色主题' : '切换深色主题'">
            {{ isDark ? '浅色' : '深色' }}
          </button>
        </div>

        <div v-if="siteConfig.allow_register" class="grid-2" style="margin-bottom: 14px;">
          <div
            class="mode-card"
            :class="{ active: !isRegisterMode }"
            @click="isRegisterMode = false; authError = ''"
          >
            账号登录
          </div>
          <div
            class="mode-card"
            :class="{ active: isRegisterMode }"
            @click="isRegisterMode = true; totpRequired = false; authError = ''"
          >
            新用户注册
          </div>
        </div>

        <div style="display: flex; flex-direction: column; gap: 14px;">
          <div>
            <label class="form-label">邮箱</label>
            <input v-model="emailInput" type="email" class="input" placeholder="name@example.com" autocomplete="username" />
          </div>
          <div>
            <label class="form-label">{{ isRegisterMode ? '设置密码（8-72 位）' : '密码' }}</label>
            <input
              v-model="passwordInput"
              type="password"
              class="input"
              :placeholder="isRegisterMode ? '至少 8 位字符' : '输入登录密码'"
              :autocomplete="isRegisterMode ? 'new-password' : 'current-password'"
              @keyup.enter="handleAuth"
            />
          </div>
          <div v-if="isRegisterMode">
            <label class="form-label">专属邀请码（选填）</label>
            <input
              v-model="inviteCodeInput"
              type="text"
              maxlength="32"
              class="input mono"
              placeholder="如有推荐邀请码请填写"
              @keyup.enter="handleAuth"
            />
          </div>
          <div v-if="!isRegisterMode && totpRequired">
            <label class="form-label">双因素认证 (2FA) 6 位动态验证码</label>
            <input
              v-model="totpInput"
              type="text"
              maxlength="6"
              class="input mono"
              placeholder="请输入验证器中的 6 位数字"
              autocomplete="one-time-code"
              @keyup.enter="handleAuth"
            />
          </div>
          <p v-if="authError" style="font-size: 12px; color: var(--danger-text);">{{ authError }}</p>
          <button @click="handleAuth" class="btn btn-primary" style="width: 100%; padding: 9px;">
            {{ isRegisterMode ? '注册并进入控制台' : '登录进入控制台' }}
          </button>
        </div>
      </div>
    </div>

    <div v-else class="app-shell">
      <div v-if="showMobileNav" class="sidebar-backdrop" @click="showMobileNav = false"></div>

      <aside class="sidebar" :class="{ 'mobile-open': showMobileNav }">
        <div class="sidebar-brand">
          <div class="sidebar-brand-left">
            <div class="brand-logo">{{ siteConfig.site_logo || 'ZP' }}</div>
            <div class="brand-title-wrap">
              <span class="brand-title">{{ siteConfig.site_name || 'Zachary Panel' }}</span>
              <span class="brand-subtitle">Cloud Relay OS</span>
            </div>
          </div>
          <button type="button" class="sidebar-close-btn" aria-label="关闭侧边菜单" @click="showMobileNav = false">✕</button>
        </div>

        <nav class="sidebar-nav">
          <div class="nav-group-label">业务中心</div>
          <button class="nav-item" :class="{ active: activeTab === 'dashboard' }" @click="switchTab('dashboard')">
            <span class="nav-item-left">
              <span class="nav-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">
                  <rect x="3" y="3" width="7" height="7" rx="1.5"></rect>
                  <rect x="14" y="3" width="7" height="7" rx="1.5"></rect>
                  <rect x="14" y="14" width="7" height="7" rx="1.5"></rect>
                  <rect x="3" y="14" width="7" height="7" rx="1.5"></rect>
                </svg>
              </span>
              <span>概览</span>
            </span>
          </button>

          <button class="nav-item" :class="{ active: activeTab === 'rules' }" @click="switchTab('rules')">
            <span class="nav-item-left">
              <span class="nav-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">
                  <polyline points="16 3 21 3 21 8"></polyline>
                  <line x1="4" y1="20" x2="21" y2="3"></line>
                  <polyline points="21 16 21 21 16 21"></polyline>
                  <line x1="15" y1="15" x2="21" y2="21"></line>
                  <line x1="4" y1="4" x2="9" y2="9"></line>
                </svg>
              </span>
              <span>转发管理</span>
            </span>
            <span class="nav-badge">{{ visibleRules.length }}</span>
          </button>

          <button class="nav-item" :class="{ active: activeTab === 'store' }" @click="switchTab('store')">
            <span class="nav-item-left">
              <span class="nav-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M6 2L3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z"></path>
                  <line x1="3" y1="6" x2="21" y2="6"></line>
                  <path d="M16 10a4 4 0 0 1-8 0"></path>
                </svg>
              </span>
              <span>套餐管理</span>
            </span>
            <span class="nav-badge">{{ plans.length }}</span>
          </button>

          <button class="nav-item" :class="{ active: activeTab === 'affiliate' }" @click="switchTab('affiliate')">
            <span class="nav-item-left">
              <span class="nav-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="18" cy="5" r="3"></circle>
                  <circle cx="6" cy="12" r="3"></circle>
                  <circle cx="18" cy="19" r="3"></circle>
                  <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line>
                  <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line>
                </svg>
              </span>
              <span>推广返利</span>
            </span>
            <span class="nav-badge">
              {{ (user?.commission_balance_cents || 0) > 0 ? '¥' + ((user?.commission_balance_cents || 0) / 100).toFixed(0) : (affiliateOverview?.commission_rate ?? siteConfig.affiliate_commission_rate ?? 10) + '%' }}
            </span>
          </button>

          <button class="nav-item" :class="{ active: activeTab === 'tickets' }" @click="switchTab('tickets')">
            <span class="nav-item-left">
              <span class="nav-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
                </svg>
              </span>
              <span>工单客服</span>
            </span>
            <span class="nav-badge">{{ pendingTicketCount > 0 ? pendingTicketCount : ticketsList.length }}</span>
          </button>

          <template v-if="isAdmin">
            <div class="nav-group-label" style="margin-top: 8px;">基础设施</div>
            <button class="nav-item" :class="{ active: activeTab === 'lines' }" @click="switchTab('lines')">
              <span class="nav-item-left">
                <span class="nav-icon">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path>
                    <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path>
                  </svg>
                </span>
                <span>隧道管理</span>
              </span>
              <span class="nav-badge">{{ lines.length }}</span>
            </button>

            <button class="nav-item" :class="{ active: activeTab === 'nodes' }" @click="switchTab('nodes')">
              <span class="nav-item-left">
                <span class="nav-icon">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
                    <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
                    <line x1="6" y1="6" x2="6.01" y2="6"></line>
                    <line x1="6" y1="18" x2="6.01" y2="18"></line>
                  </svg>
                </span>
                <span>节点管理</span>
              </span>
              <span class="nav-badge">{{ nodes.length }}</span>
            </button>

            <div class="nav-group-label" style="margin-top: 8px;">权限与系统</div>
            <button class="nav-item" :class="{ active: activeTab === 'roles' }" @click="switchTab('roles')">
              <span class="nav-item-left">
                <span class="nav-icon">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                    <path d="m9 12 2 2 4-4"></path>
                  </svg>
                </span>
                <span>角色管理</span>
              </span>
              <span class="nav-badge">{{ rolesList.length }}</span>
            </button>

            <button class="nav-item" :class="{ active: activeTab === 'users' }" @click="switchTab('users')">
              <span class="nav-item-left">
                <span class="nav-icon">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
                    <circle cx="9" cy="7" r="4"></circle>
                    <path d="M23 21v-2a4 4 0 0 0-3-3.87"></path>
                    <path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
                  </svg>
                </span>
                <span>用户管理</span>
              </span>
              <span class="nav-badge">{{ usersList.length }}</span>
            </button>

            <button class="nav-item" :class="{ active: activeTab === 'settings' }" @click="switchTab('settings')">
              <span class="nav-item-left">
                <span class="nav-icon">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="3"></circle>
                    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
                  </svg>
                </span>
                <span>系统设置</span>
              </span>
            </button>
          </template>
        </nav>

        <div class="sidebar-footer">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <span style="font-weight: 600; color: #f8fafc;">{{ isAdmin ? '管理员配额' : planNameById(user?.plan_id) }}</span>
            <span style="font-weight: 700; color: #7dd3fc;">{{ quotaPercent }}%</span>
          </div>
          <div class="progress-track" style="background: rgba(255, 255, 255, 0.1); margin-top: 4px;">
            <div class="progress-fill" :style="{ width: quotaPercent + '%' }"></div>
          </div>
          <div style="display: flex; justify-content: space-between; color: #94a3b8; margin-top: 8px; font-size: 11.5px;">
            <span>{{ formatBytes(user?.used_bytes || 0) }} / {{ formatBytes(user?.quota_bytes || 0) }}</span>
            <span>{{ user?.speed_mbps || 100 }}M</span>
          </div>
        </div>
      </aside>

      <div class="main-area">
        <header class="topbar">
          <div class="topbar-title-group">
            <button type="button" class="mobile-nav-btn" aria-label="打开导航菜单" @click="showMobileNav = true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
                <line x1="3" y1="6" x2="21" y2="6"></line>
                <line x1="3" y1="12" x2="21" y2="12"></line>
                <line x1="3" y1="18" x2="21" y2="18"></line>
              </svg>
            </button>
            <h1 class="topbar-title">{{ currentTabTitle }}</h1>
            <button
              type="button"
              class="topbar-pill"
              :class="{ paused: !autoRefresh || !isPageVisible }"
              :title="autoRefresh ? '点击可暂停 3 秒实时轮询（后台标签页自动暂停）' : '点击恢复 3 秒实时轮询'"
              style="cursor: pointer;"
              @click="autoRefresh = !autoRefresh"
            >
              <span class="pulse-dot"></span>
              <span>{{ !autoRefresh ? '轮询已暂停' : isPageVisible ? '实时同步' : '后台休眠' }}</span>
            </button>
          </div>
          <div class="topbar-actions">
            <button type="button" class="cmdk-trigger" @click="openCommandPalette" title="快速搜索与跳转 (Ctrl/Cmd + K)">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="11" cy="11" r="8"></circle>
                <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
              </svg>
              <span class="cmdk-trigger-label">快速检索</span>
              <kbd class="kbd-shortcut">⌘K</kbd>
            </button>
            <button @click="openPasswordModal" class="btn btn-soft btn-sm">安全 / 2FA</button>
            <button @click="toggleTheme" class="btn btn-outline btn-sm" :title="isDark ? '切换浅色主题' : '切换深色主题'">
              {{ isDark ? '浅色' : '深色' }}
            </button>
            <div class="user-chip">
              <span class="user-avatar">{{ (user?.email || 'U').charAt(0) }}</span>
              <span class="user-chip-email">{{ user?.email }}</span>
              <span class="badge" :class="isAdmin ? 'badge-purple' : 'badge-primary'">
                {{ isAdmin ? '管理员' : roleNameById(user?.role_group_id) }}
              </span>
            </div>
            <button @click="logout" class="btn btn-outline btn-sm">退出</button>
          </div>
        </header>

        <main class="page-container">
          <!-- 概览 -->
          <div v-if="activeTab === 'dashboard'" style="display: flex; flex-direction: column; gap: 16px;">
            <div
              v-if="siteConfig.announcement"
              class="card"
              style="padding: 12px 16px; display: flex; align-items: center; gap: 10px; background: var(--primary-soft); border-color: transparent;"
            >
              <span class="badge badge-primary">公告</span>
              <span style="font-size: 13px; color: var(--text-main);">{{ siteConfig.announcement }}</span>
            </div>

            <div
              v-if="siteConfig.offpeak_enabled"
              class="card"
              style="padding: 10px 16px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; background: var(--bg-soft);"
            >
              <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap; font-size: 12.5px;">
                <span class="badge badge-success">闲时优惠已开启</span>
                <span>
                  每日 <strong class="mono">{{ siteConfig.offpeak_start || '00:00' }} ~ {{ siteConfig.offpeak_end || '08:00' }}</strong>
                  ({{ siteConfig.offpeak_timezone || 'Asia/Shanghai' }}) 转发流量自动按
                  <strong class="mono">×{{ siteConfig.offpeak_multiplier ?? 0.5 }}</strong> 折算计费
                </span>
              </div>
            </div>

            <div class="grid-4">
              <div class="card">
                <div class="metric-label">已用流量</div>
                <div class="metric-value" style="font-size: 18px; margin-top: 6px;">
                  {{ formatBytes(user?.used_bytes || 0) }}
                  <span style="font-size: 13px; font-weight: 400; color: var(--text-muted);">
                    / {{ formatBytes(user?.quota_bytes || 0) }}
                  </span>
                </div>
                <div class="progress-track">
                  <div class="progress-fill" :style="{ width: quotaPercent + '%' }"></div>
                </div>
              </div>
              <div class="card">
                <div class="metric-label">转发规则</div>
                <div class="metric-value">
                  {{ visibleRules.filter((r) => r.enabled).length }} / {{ user?.max_rules || 0 }}
                </div>
              </div>
              <div class="card">
                <div class="metric-label">{{ isAdmin ? '隧道数量' : '可用隧道' }}</div>
                <div class="metric-value">{{ authorizedLines.length }}</div>
              </div>
              <div class="card">
                <div class="metric-label">{{ isAdmin ? '在线节点' : '带宽限速' }}</div>
                <div v-if="isAdmin" class="metric-value">
                  {{ nodes.filter((n) => n.status === 'online').length }} / {{ nodes.length }}
                </div>
                <div v-else class="metric-value">{{ user?.speed_mbps || 100 }} Mbps</div>
              </div>
            </div>

            <!-- 个人订阅信息与快捷订阅链接 -->
            <div class="card" style="display: flex; flex-direction: column; gap: 12px;">
              <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                  <span style="font-weight: 600; font-size: 14px;">我的订阅与链接</span>
                  <span class="badge badge-primary">{{ isAdmin ? '管理员账号' : planNameById(user?.plan_id) }}</span>
                  <span v-if="!isAdmin" class="badge" :class="isUserExpired(user) ? 'badge-danger' : 'badge-neutral'">
                    到期：{{ formatDateDisplay(user?.expire_at) }}{{ isUserExpired(user) ? '（已过期）' : '' }}
                  </span>
                  <span class="badge badge-neutral">
                    余额：¥{{ ((user?.balance_cents || 0) / 100).toFixed(2) }}
                  </span>
                </div>
                <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                  <button
                    v-if="currentBoundPlan && currentBoundPlan.price_cents > 0"
                    @click="handleResetSubscription"
                    class="btn btn-soft btn-sm"
                  >
                    付费重置流量周期 (¥{{ (currentBoundPlan.price_cents / 100).toFixed(2) }})
                  </button>
                  <button @click="handleResetSubToken" class="btn btn-outline btn-sm">重置订阅链接</button>
                </div>
              </div>
              <div
                v-if="currentSubscriptionUrl"
                style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;"
              >
                <input
                  :value="currentSubscriptionUrl"
                  readonly
                  class="input"
                  style="flex: 1; min-width: 240px; font-family: monospace; font-size: 12px;"
                  @focus="($event.target as HTMLInputElement)?.select()"
                />
                <button @click="copyConnectAddr(currentSubscriptionUrl)" class="btn btn-primary btn-sm">
                  复制订阅链接
                </button>
                <button
                  @click="copyConnectAddr(subscriptionUrlForToken(user?.sub_token, '?format=json'))"
                  class="btn btn-outline btn-sm"
                >
                  复制 JSON 订阅
                </button>
              </div>
            </div>

            <!-- 24 小时流量趋势图 -->
            <div class="card" style="display: flex; flex-direction: column; gap: 12px;">
              <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                <div style="display: flex; align-items: center; gap: 10px;">
                  <span style="font-weight: 600; font-size: 14px;">近 24 小时流量趋势</span>
                  <span class="badge badge-primary">24h 合计计费：{{ formatBytes(total24hBilled) }}</span>
                </div>
                <div v-if="isAdmin" style="display: flex; gap: 6px;">
                  <button
                    class="btn btn-sm"
                    :class="chartViewScope === 'global' ? 'btn-primary' : 'btn-soft'"
                    @click="chartViewScope = 'global'"
                  >
                    全站总流量
                  </button>
                  <button
                    class="btn btn-sm"
                    :class="chartViewScope === 'personal' ? 'btn-primary' : 'btn-soft'"
                    @click="chartViewScope = 'personal'"
                  >
                    仅我个人
                  </button>
                </div>
              </div>

              <div
                style="display: grid; grid-template-columns: repeat(24, minmax(0, 1fr)); align-items: end; gap: 4px; height: 110px; padding: 10px 6px 4px; background: var(--bg-soft); border-radius: var(--radius-md); border: 1px solid var(--border-color);"
              >
                <div
                  v-for="pt in activeHourlySeries"
                  :key="pt.hour_bucket"
                  :title="`${pt.hour_bucket}\n上行: ${formatBytes(pt.upload_bytes)}\n下行: ${formatBytes(pt.down_bytes)}\n计费: ${formatBytes(pt.billed_bytes)}`"
                  style="display: flex; flex-direction: column; align-items: center; justify-content: flex-end; height: 100%; gap: 4px;"
                >
                  <div
                    style="width: 100%; max-width: 18px; border-radius: 3px 3px 0 0; background: var(--primary); transition: height 0.25s ease;"
                    :style="{
                      height: Math.max(4, Math.round(((pt.billed_bytes || 0) / maxHourlyBilled) * 76)) + 'px',
                      opacity: pt.billed_bytes > 0 ? 0.92 : 0.22,
                    }"
                  ></div>
                  <span style="font-size: 9.5px; color: var(--text-muted); white-space: nowrap;">
                    {{ pt.hour_bucket.slice(11, 13) }}
                  </span>
                </div>
              </div>
            </div>

            <!-- 管理员可见：流量消耗 Top 5 用户与节点排行 -->
            <div v-if="isAdmin" class="grid-2">
              <div class="card" style="display: flex; flex-direction: column; gap: 10px;">
                <div style="font-weight: 600; font-size: 14px;">用户累计流量 Top 5</div>
                <div
                  v-for="(tu, idx) in topUsers"
                  :key="tu.id"
                  style="display: flex; justify-content: space-between; align-items: center; font-size: 12.5px; padding: 6px 8px; border-radius: var(--radius-sm); background: var(--bg-soft);"
                >
                  <div style="display: flex; align-items: center; gap: 8px;">
                    <span class="badge badge-neutral">#{{ idx + 1 }}</span>
                    <span style="font-weight: 500;">{{ tu.email }}</span>
                  </div>
                  <span style="font-family: monospace; color: var(--text-secondary);">
                    {{ formatBytes(tu.used_bytes) }} / {{ formatBytes(tu.quota_bytes) }}
                  </span>
                </div>
              </div>

              <div class="card" style="display: flex; flex-direction: column; gap: 10px;">
                <div style="font-weight: 600; font-size: 14px;">节点累计流量 Top 5</div>
                <div
                  v-for="(tn, idx) in topNodes"
                  :key="tn.id"
                  style="display: flex; justify-content: space-between; align-items: center; font-size: 12.5px; padding: 6px 8px; border-radius: var(--radius-sm); background: var(--bg-soft);"
                >
                  <div style="display: flex; align-items: center; gap: 8px;">
                    <span class="badge badge-neutral">#{{ idx + 1 }}</span>
                    <span style="font-weight: 500;">{{ tn.name }}</span>
                  </div>
                  <span style="font-family: monospace; color: var(--text-secondary);">
                    {{ formatBytes(tn.used_bytes) }} / {{ tn.quota_bytes > 0 ? formatBytes(tn.quota_bytes) : '不限' }}
                  </span>
                </div>
              </div>
            </div>

            <!-- 管理员可见：服务器硬件与流量探针 -->
            <div v-if="isAdmin" class="grid-3">
              <div
                v-for="node in nodes"
                :key="node.id"
                class="card probe-card"
                style="display: flex; flex-direction: column; gap: 12px;"
              >
                <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px;">
                  <span style="font-weight: 600; font-size: 14px;">{{ node.name }}</span>
                  <span
                    class="badge"
                    :class="node.status === 'online' ? 'badge-success' : node.status === 'maintenance' ? 'badge-warning' : 'badge-danger'"
                  >
                    <span class="dot"></span>
                    {{ node.status === 'online' ? '在线' : node.status === 'maintenance' ? '维护中' : '离线' }}
                  </span>
                </div>

                <div>
                  <div style="display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px;">
                    <span style="color: var(--text-secondary);">
                      CPU ({{ node.cpu_cores || 4 }}核) · 负载 {{ (node.load_1 || 0).toFixed(2) }}
                    </span>
                    <span style="font-weight: 600;">{{ (node.cpu_usage || 0).toFixed(1) }}%</span>
                  </div>
                  <div class="progress-track" style="margin-top: 0;">
                    <div class="progress-fill" :style="{ width: Math.min(100, node.cpu_usage || 0) + '%' }"></div>
                  </div>
                </div>

                <div>
                  <div style="display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px;">
                    <span style="color: var(--text-secondary);">
                      内存 {{ formatBytes(node.mem_used_bytes) }} / {{ formatBytes(node.mem_total_bytes) }}
                    </span>
                    <span style="font-weight: 600;">{{ (node.mem_usage || 0).toFixed(1) }}%</span>
                  </div>
                  <div class="progress-track" style="margin-top: 0;">
                    <div class="progress-fill" :style="{ width: Math.min(100, node.mem_usage || 0) + '%' }"></div>
                  </div>
                </div>

                <div>
                  <div style="display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px;">
                    <span style="color: var(--text-secondary);">
                      硬盘 {{ formatBytes(node.disk_used_bytes) }} / {{ formatBytes(node.disk_total_bytes) }}
                    </span>
                    <span style="font-weight: 600;">{{ (node.disk_usage || 0).toFixed(1) }}%</span>
                  </div>
                  <div class="progress-track" style="margin-top: 0;">
                    <div class="progress-fill" :style="{ width: Math.min(100, node.disk_usage || 0) + '%' }"></div>
                  </div>
                </div>

                <div>
                  <div style="display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px;">
                    <span style="color: var(--text-secondary);">
                      流量 {{ formatBytes(node.used_bytes) }} /
                      {{ node.quota_bytes > 0 ? formatBytes(node.quota_bytes) : '不限' }}
                    </span>
                    <span style="font-weight: 600;">{{ nodeTrafficPercent(node) }}%</span>
                  </div>
                  <div class="progress-track" style="margin-top: 0;">
                    <div class="progress-fill" :style="{ width: nodeTrafficPercent(node) + '%', background: '#10b981' }"></div>
                  </div>
                </div>

                <div
                  style="display: flex; justify-content: space-between; align-items: center; padding-top: 8px; border-top: 1px solid var(--border-color); font-size: 11.5px; color: var(--text-muted);"
                >
                  <span>连接 {{ node.active_conns || 0 }}</span>
                  <span>{{ formatUptime(node.uptime_seconds) }}</span>
                </div>
              </div>
            </div>

            <!-- 普通用户可见：已授权隧道列表 -->
            <div v-else class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>授权隧道</th>
                    <th>类型与增强能力</th>
                    <th>转发方式</th>
                    <th>入口地址</th>
                    <th>计费</th>
                    <th style="text-align: right;">操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="line in authorizedLines" :key="line.id">
                    <td style="font-weight: 500;">{{ line.name }}</td>
                    <td>
                      <div style="display: flex; align-items: center; gap: 4px; flex-wrap: wrap;">
                        <span class="badge" :class="line.type === 'encrypt' ? 'badge-purple' : 'badge-primary'">
                          {{ line.type === 'encrypt' ? '隧道转发' : '端口转发' }}
                        </span>
                        <span v-if="line.enable_mux" class="badge badge-info">Mux复用</span>
                        <span v-if="line.enable_bonding" class="badge badge-success">聚合×{{ line.bond_links || 4 }}</span>
                        <span v-if="line.proxy_protocol" class="badge badge-neutral">PROXY v{{ line.proxy_protocol }}</span>
                      </div>
                    </td>
                    <td><span class="badge badge-neutral">{{ line.engine }}</span></td>
                    <td>{{ nodeConnectIPById(line.ingress_node_id) }}</td>
                    <td>
                      {{ line.billing_mode === 'one_way' ? '单向' : '双向' }} · {{ line.rate_multiplier }}x
                      <span
                        v-if="siteConfig.offpeak_enabled && (line.offpeak_multiplier || 0) > 0"
                        class="badge badge-success"
                        style="margin-left: 4px;"
                      >
                        闲时×{{ line.offpeak_multiplier }}
                      </span>
                    </td>
                    <td style="text-align: right;">
                      <button @click="quickCreateRuleForTunnel(line)" class="btn btn-soft btn-sm">创建转发</button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- 转发管理 -->
          <div v-if="activeTab === 'rules'" style="display: flex; flex-direction: column; gap: 14px;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
              <div style="font-size: 12.5px; color: var(--text-secondary);">
                可用隧道：
                <span
                  v-for="l in authorizedLines"
                  :key="l.id"
                  class="badge badge-neutral"
                  style="margin-right: 4px;"
                >
                  {{ l.name }}
                </span>
                <span v-if="authorizedLines.length === 0" style="color: var(--danger-text);">无可用隧道权限</span>
              </div>
              <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                <button
                  v-if="validSelectedRuleIds.length > 0"
                  @click="handleBatchDeleteRules"
                  class="btn btn-danger"
                >
                  批量删除 ({{ validSelectedRuleIds.length }})
                </button>
                <button @click="exportRulesToClipboard" class="btn btn-outline">
                  {{ validSelectedRuleIds.length > 0 ? `导出已选 (${validSelectedRuleIds.length})` : '导出规则' }}
                </button>
                <button @click="exportRulesToCSV" class="btn btn-outline">导出 CSV</button>
                <button @click="openBatchModal" class="btn btn-soft">批量导入</button>
                <button @click="openCreateRuleModal" class="btn btn-primary">+ 新增转发</button>
              </div>
            </div>

            <!-- 规则搜索与多维筛选栏 -->
            <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
              <input
                v-model="ruleSearchQuery"
                class="input"
                style="width: 260px;"
                :placeholder="isAdmin ? '搜索名称 / 端口 / SNI域名 / 目标 / 邮箱' : '搜索名称 / 端口 / SNI域名 / 目标地址'"
              />
              <select v-model="ruleFilterTunnelId" class="select" style="width: 150px;">
                <option :value="0">全部隧道</option>
                <option v-for="l in authorizedLines" :key="l.id" :value="l.id">{{ l.name }}</option>
              </select>
              <select v-model="ruleFilterProtocol" class="select" style="width: 120px;">
                <option value="all">全部协议</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="both">TCP+UDP</option>
              </select>
              <select v-model="ruleFilterStatus" class="select" style="width: 135px;">
                <option value="all">全部状态</option>
                <option value="running">正常运行</option>
                <option value="paused">已暂停</option>
                <option value="quota_exceeded">限额耗尽</option>
              </select>
              <span style="font-size: 12px; color: var(--text-muted); margin-left: auto;">
                共 {{ filteredRules.length }} / {{ visibleRules.length }} 条规则
              </span>
            </div>

            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th style="width: 36px; text-align: center;">
                      <input
                        type="checkbox"
                        :checked="allVisibleSelected"
                        :disabled="pagedRules.length === 0"
                        @change="toggleSelectAllRules"
                        title="全选 / 取消全选当前页"
                        style="cursor: pointer;"
                      />
                    </th>
                    <th>名称 / 路由增强</th>
                    <th v-if="isAdmin">所属用户</th>
                    <th>隧道</th>
                    <th>转发方式</th>
                    <th>连接地址</th>
                    <th>目标地址与分段诊断</th>
                    <th>流量 / 限额</th>
                    <th>状态</th>
                    <th style="text-align: right;">操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="rule in pagedRules" :key="rule.id">
                    <td style="text-align: center;">
                      <input
                        type="checkbox"
                        :value="rule.id"
                        v-model="selectedRuleIds"
                        style="cursor: pointer;"
                      />
                    </td>
                    <td>
                      <div style="font-weight: 500;">{{ rule.name }}</div>
                      <div style="display: flex; align-items: center; gap: 4px; flex-wrap: wrap; margin-top: 3px;">
                        <span style="font-size: 11.5px; color: var(--text-muted);">{{ rule.protocol.toUpperCase() }}</span>
                        <span
                          v-if="parseTargets(rule.targets_json).length > 1"
                          class="badge badge-neutral"
                          style="font-size: 10.5px;"
                        >
                          {{ loadBalanceLabel(rule.load_balance) }}
                        </span>
                        <span
                          v-if="effectiveRuleProxyProto(rule) > 0"
                          class="badge badge-info"
                          style="font-size: 10.5px;"
                          title="向下游注入真实客户端源 IP"
                        >
                          PROXY v{{ effectiveRuleProxyProto(rule) }}
                        </span>
                        <span
                          v-if="rule.outbound_ip"
                          class="badge badge-neutral mono"
                          style="font-size: 10.5px;"
                          title="绑定指定出口网卡源 IP"
                        >
                          源:{{ rule.outbound_ip }}
                        </span>
                      </div>
                      <div v-if="rule.match_domains" style="margin-top: 3px;">
                        <span
                          class="badge badge-primary mono"
                          style="font-size: 10.5px;"
                          title="TLS SNI / HTTP Host 共享端口路由域名"
                        >
                          SNI: {{ rule.match_domains }}
                        </span>
                      </div>
                    </td>
                    <td v-if="isAdmin" style="font-size: 12.5px; color: var(--text-secondary);">
                      {{ userEmailById(rule.user_id) }}
                    </td>
                    <td>
                      <span
                        class="badge"
                        :class="getTunnelById(rule.tunnel_line_id)?.type === 'encrypt' ? 'badge-purple' : 'badge-primary'"
                      >
                        {{ getTunnelById(rule.tunnel_line_id)?.name || '-' }}
                      </span>
                    </td>
                    <td>
                      <span
                        class="badge badge-neutral"
                        :title="ruleEngineFallback(rule) ? '已开启限速或高级隧道特性，实际以 native 引擎运行' : ''"
                      >
                        {{ rule.effective_engine || getTunnelById(rule.tunnel_line_id)?.engine || rule.engine }}
                        <template v-if="ruleEngineFallback(rule)">（自动切换）</template>
                      </span>
                    </td>
                    <td>
                      <button
                        class="copy-pill"
                        title="点击复制"
                        @click="copyConnectAddr(nodeConnectIPById(rule.ingress_node_id) + ':' + rule.listen_port)"
                      >
                        {{ nodeConnectIPById(rule.ingress_node_id) }}:{{ rule.listen_port }}
                      </button>
                    </td>
                    <td>
                      <div
                        v-if="probeResults[rule.id]?.legs && probeResults[rule.id].legs!.length > 0"
                        style="display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 4px;"
                      >
                        <span
                          v-for="(leg, lIdx) in probeResults[rule.id].legs"
                          :key="lIdx"
                          class="badge"
                          :class="leg.latency_ms > 0 ? 'badge-info' : 'badge-danger'"
                          style="font-size: 10.5px;"
                        >
                          {{ leg.from_name }}→{{ leg.to_name }}:
                          {{ leg.latency_ms > 0 ? leg.latency_ms + 'ms' : '超时' }}
                        </span>
                      </div>
                      <div
                        v-for="(t, idx) in parseTargets(rule.targets_json)"
                        :key="idx"
                        style="display: flex; align-items: center; gap: 6px; flex-wrap: wrap;"
                      >
                        <span class="mono" style="font-size: 12.5px;">{{ t.address }}</span>
                        <span v-if="t.weight && t.weight !== 100" class="badge badge-neutral" style="font-size: 10px;">
                          w={{ t.weight }}
                        </span>
                        <span v-if="t.backup" class="badge badge-warning" style="font-size: 10px;">备</span>
                        <span
                          v-if="probeResults[rule.id]?.latencies?.[t.address] !== undefined"
                          class="badge"
                          :class="probeResults[rule.id].latencies[t.address] > 0 ? 'badge-success' : 'badge-danger'"
                        >
                          <template v-if="probeResults[rule.id].latencies[t.address] > 0">
                            {{
                              (probeResults[rule.id].tunnel_ms || 0) > 0
                                ? `链路 ${probeResults[rule.id].tunnel_ms}ms + 落地 ${probeResults[rule.id].latencies[t.address]}ms`
                                : `${probeResults[rule.id].latencies[t.address]}ms`
                            }}
                          </template>
                          <template v-else>超时</template>
                        </span>
                      </div>
                    </td>
                    <td>
                      <div class="mono">
                        {{ formatBytes(rule.billed_bytes) }}
                        <span v-if="(rule.rule_quota_bytes || 0) > 0" style="font-size: 11.5px; color: var(--text-muted);">
                          / {{ formatBytes(rule.rule_quota_bytes || 0) }}
                        </span>
                      </div>
                      <div
                        v-if="(rule.daily_quota_bytes || 0) > 0"
                        class="mono"
                        style="font-size: 11px; color: var(--text-muted); margin-top: 2px;"
                      >
                        今日: {{ formatBytes(rule.daily_used_bytes || 0) }} / {{ formatBytes(rule.daily_quota_bytes || 0) }}
                      </div>
                    </td>
                    <td>
                      <span
                        class="badge"
                        :class="ruleStatusBadge(rule)"
                        :title="rule.last_error || ''"
                      >
                        <span class="dot"></span> {{ ruleStatusLabel(rule) }}
                      </span>
                    </td>
                    <td style="text-align: right; white-space: nowrap;">
                      <button @click="openEditRuleModal(rule)" class="btn btn-soft btn-sm" style="margin-right: 4px;">
                        编辑
                      </button>
                      <button @click="handleProbeRule(rule)" class="btn btn-outline btn-sm" style="margin-right: 4px;">
                        {{ probingRuleId === rule.id ? '...' : '测速' }}
                      </button>
                      <button @click="handleToggleRule(rule)" class="btn btn-outline btn-sm" style="margin-right: 4px;">
                        {{ rule.enabled ? '暂停' : '启用' }}
                      </button>
                      <button @click="handleDeleteRule(rule.id)" class="btn btn-danger btn-sm">删除</button>
                    </td>
                  </tr>
                  <tr v-if="filteredRules.length === 0">
                    <td :colspan="isAdmin ? 10 : 9" style="padding: 0;">
                      <div class="empty-state">
                        <div class="empty-state-icon">
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                            <polyline points="16 3 21 3 21 8"></polyline>
                            <line x1="4" y1="20" x2="21" y2="3"></line>
                            <polyline points="21 16 21 21 16 21"></polyline>
                            <line x1="15" y1="15" x2="21" y2="21"></line>
                            <line x1="4" y1="4" x2="9" y2="9"></line>
                          </svg>
                        </div>
                        <div class="empty-state-title">
                          {{ visibleRules.length === 0 ? '暂无转发规则' : '没有匹配筛选条件的规则' }}
                        </div>
                        <div class="empty-state-desc">
                          {{
                            visibleRules.length === 0
                              ? '点击右上角「+ 新增转发」或「批量导入」立即创建第一条转发规则'
                              : '请调整关键词、隧道或状态筛选条件后重试'
                          }}
                        </div>
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
              <div v-if="filteredRules.length > 0" class="pagination-bar">
                <span>第 {{ rulesPage }} / {{ rulesTotalPages }} 页 · 共 {{ filteredRules.length }} 条规则</span>
                <div class="pagination-controls">
                  <select v-model.number="rulesPageSize" class="select pagination-select">
                    <option :value="20">20 条/页</option>
                    <option :value="50">50 条/页</option>
                    <option :value="100">100 条/页</option>
                  </select>
                  <button class="btn btn-outline btn-sm" :disabled="rulesPage <= 1" @click="rulesPage--">上一页</button>
                  <button class="btn btn-outline btn-sm" :disabled="rulesPage >= rulesTotalPages" @click="rulesPage++">下一页</button>
                </div>
              </div>
            </div>
          </div>

          <!-- 隧道管理 (仅管理员) -->
          <div v-if="activeTab === 'lines' && isAdmin" style="display: flex; flex-direction: column; gap: 14px;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
              <span style="font-size: 12.5px; color: var(--text-secondary);">
                支持单跳直连、3+ 跳链式转发、多出口带宽聚合池、连接复用池 (Mux)、单流多通道条带化聚合 (Bonding) 与 PROXY Protocol v1/v2。
              </span>
              <button @click="openCreateLineModal" class="btn btn-primary">+ 新增隧道</button>
            </div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>名称 / 增强特性</th>
                    <th>类型</th>
                    <th>转发方式</th>
                    <th>链路拓扑 (入口 → 跳点 → 出口池)</th>
                    <th>计费 / 闲时</th>
                    <th>规则数</th>
                    <th style="text-align: right;">操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="line in lines" :key="line.id">
                    <td>
                      <div style="font-weight: 500;">{{ line.name }}</div>
                      <div style="display: flex; gap: 4px; flex-wrap: wrap; margin-top: 3px;">
                        <span v-if="line.enable_mux" class="badge badge-info" style="font-size: 10.5px;">Mux复用池</span>
                        <span v-if="line.enable_bonding" class="badge badge-success" style="font-size: 10.5px;">
                          Bond×{{ line.bond_links || 4 }}聚合
                        </span>
                        <span v-if="line.proxy_protocol" class="badge badge-neutral" style="font-size: 10.5px;">
                          PROXY v{{ line.proxy_protocol }}
                        </span>
                        <span
                          v-if="line.type === 'encrypt' && parseLineEgressCount(line) > 1"
                          class="badge badge-primary"
                          style="font-size: 10.5px;"
                        >
                          {{ loadBalanceLabel(line.load_balance) }}
                        </span>
                      </div>
                    </td>
                    <td>
                      <span class="badge" :class="line.type === 'encrypt' ? 'badge-purple' : 'badge-primary'">
                        {{ line.type === 'encrypt' ? '隧道转发' : '端口转发' }}
                      </span>
                    </td>
                    <td><span class="badge badge-neutral">{{ line.engine }}</span></td>
                    <td>
                      <div v-if="line.type === 'direct'" style="font-size: 12.5px;">
                        {{ nodeNameById(line.ingress_node_id) }} <span style="color: var(--text-muted);">(单节点直转)</span>
                      </div>
                      <div v-else style="display: flex; align-items: center; gap: 4px; flex-wrap: wrap; font-size: 12.5px;">
                        <span class="badge badge-primary">{{ nodeNameById(line.ingress_node_id) }}</span>
                        <template v-for="hid in parseAllowedIds(line.hop_node_ids)" :key="'h-' + hid">
                          <span style="color: var(--text-muted);">→</span>
                          <span class="badge badge-info">跳:{{ nodeNameById(hid) }}</span>
                        </template>
                        <span style="color: var(--text-muted);">→</span>
                        <span v-if="parseLineEgressCount(line) <= 1" class="badge badge-purple">
                          {{ nodeNameById(line.egress_node_id) }} ({{ line.transport.toUpperCase() }})
                        </span>
                        <span
                          v-else
                          class="badge badge-purple"
                          :title="line.egress_node_ids"
                        >
                          多出口池×{{ parseLineEgressCount(line) }} ({{ line.transport.toUpperCase() }})
                        </span>
                      </div>
                    </td>
                    <td>
                      <div>{{ line.billing_mode === 'one_way' ? '单向' : '双向' }} · {{ line.rate_multiplier }}x</div>
                      <div v-if="(line.offpeak_multiplier || 0) > 0" style="font-size: 11px; color: var(--success-text);">
                        专属闲时 ×{{ line.offpeak_multiplier }}
                      </div>
                    </td>
                    <td>
                      {{ lineRuleCountMap.get(line.id) || 0 }} / {{ line.max_port_count || 50 }}
                      <div v-if="line.port_range" style="font-size: 12px; color: var(--text-muted);">端口 {{ line.port_range }}</div>
                    </td>
                    <td style="text-align: right; white-space: nowrap;">
                      <button
                        @click="quickCreateRuleForTunnel(line)"
                        class="btn btn-soft btn-sm"
                        style="margin-right: 4px;"
                      >
                        添加转发
                      </button>
                      <button @click="openEditLineModal(line)" class="btn btn-outline btn-sm" style="margin-right: 4px;">
                        编辑
                      </button>
                      <button @click="deleteLine(line.id)" class="btn btn-danger btn-sm">删除</button>
                    </td>
                  </tr>
                  <tr v-if="lines.length === 0">
                    <td colspan="7" style="padding: 0;">
                      <div class="empty-state">
                        <div class="empty-state-title">暂无隧道线路</div>
                        <div class="empty-state-desc">点击右上角「+ 新增隧道」配置端口转发、多跳链式或带宽聚合隧道</div>
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- 节点管理与多入口 DNS 容灾 (仅管理员) -->
          <div v-if="activeTab === 'nodes' && isAdmin" style="display: flex; flex-direction: column; gap: 16px;">
            <div style="display: flex; justify-content: flex-end; gap: 8px; flex-wrap: wrap;">
              <button @click="openCreateFailoverModal" class="btn btn-outline">+ 新增 DNS 自动容灾组</button>
              <button @click="batchUpgradeOnlineNodes" class="btn btn-soft">一键升级在线节点</button>
              <button @click="openCreateNodeModal" class="btn btn-primary">+ 新增节点</button>
            </div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>名称 / 版本</th>
                    <th>连接地址</th>
                    <th>节点 IP / 出站源 IP</th>
                    <th>端口范围</th>
                    <th>倍率</th>
                    <th>流量</th>
                    <th>状态</th>
                    <th style="text-align: right;">操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="node in nodes" :key="node.id">
                    <td style="font-weight: 500;">
                      <div>{{ node.name }}</div>
                      <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">
                        Agent v{{ node.agent_version || '1.1.0-sec' }}
                      </div>
                    </td>
                    <td>
                      <button class="copy-pill" @click="copyConnectAddr(node.connect_ip || node.public_host)">
                        {{ node.connect_ip || node.public_host }}
                      </button>
                    </td>
                    <td>
                      <div class="mono" style="color: var(--text-secondary);">{{ node.server_ip }}</div>
                      <div v-if="node.outbound_ip" style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">
                        默认出站: <span class="mono">{{ node.outbound_ip }}</span>
                      </div>
                      <div v-if="node.allowed_outbound_ips" style="font-size: 11px; color: var(--primary-text); margin-top: 1px;">
                        授权池: <span class="mono">{{ node.allowed_outbound_ips }}</span>
                      </div>
                    </td>
                    <td class="mono" style="color: var(--text-secondary);">{{ node.port_range }}</td>
                    <td>{{ node.traffic_rate || 1 }}x</td>
                    <td>
                      <div>
                        {{ formatBytes(node.used_bytes) }} /
                        {{ node.quota_bytes > 0 ? formatBytes(node.quota_bytes) : '不限' }}
                      </div>
                      <div v-if="node.reset_day && node.reset_day > 0" style="font-size: 11.5px; color: var(--text-muted);">
                        每月 {{ node.reset_day }} 号自动重置
                      </div>
                    </td>
                    <td>
                      <span
                        class="badge"
                        :class="node.status === 'online' ? 'badge-success' : node.status === 'maintenance' ? 'badge-warning' : 'badge-danger'"
                      >
                        <span class="dot"></span>
                        {{ node.status === 'online' ? '在线' : node.status === 'maintenance' ? '维护中' : '离线' }}
                      </span>
                    </td>
                    <td style="text-align: right; white-space: nowrap;">
                      <button @click="openInstallCmd(node.id)" class="btn btn-soft btn-sm" style="margin-right: 4px;">
                        对接
                      </button>
                      <button @click="upgradeNodeRemote(node)" class="btn btn-outline btn-sm" style="margin-right: 4px;">
                        升级
                      </button>
                      <button @click="resyncNodeRules(node)" class="btn btn-outline btn-sm" style="margin-right: 4px;">
                        同步
                      </button>
                      <button @click="resetNodeTraffic(node)" class="btn btn-outline btn-sm" style="margin-right: 4px;">
                        重置流量
                      </button>
                      <button @click="openEditNodeModal(node)" class="btn btn-outline btn-sm" style="margin-right: 4px;">
                        编辑
                      </button>
                      <button @click="deleteNode(node.id)" class="btn btn-danger btn-sm">删除</button>
                    </td>
                  </tr>
                  <tr v-if="nodes.length === 0">
                    <td colspan="8" style="padding: 0;">
                      <div class="empty-state">
                        <div class="empty-state-title">暂无转发节点</div>
                        <div class="empty-state-desc">点击右上角「+ 新增节点」添加转发服务器并获取一键对接命令</div>
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <!-- 多入口高可用与 DNS 自动容灾切换 -->
            <div class="card" style="display: flex; flex-direction: column; gap: 12px;">
              <div style="display: flex; justify-content: space-between; align-items: center; gap: 10px; flex-wrap: wrap;">
                <div>
                  <div style="font-weight: 600; font-size: 14px;">多入口高可用与 DNS 自动容灾切换 (DNS Failover)</div>
                  <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">
                    实时巡检主入口与备用入口队列，节点掉线或进入维护模式超阈值后自动切换 Cloudflare / DNSPod / Webhook A/AAAA 解析并支持防抖回切
                  </div>
                </div>
                <button @click="openCreateFailoverModal" class="btn btn-primary btn-sm">+ 新增 DNS 容灾组</button>
              </div>

              <div class="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>容灾组 / 域名</th>
                      <th>服务商</th>
                      <th>主入口 → 备用入口队列</th>
                      <th>当前解析节点 / IP</th>
                      <th>阈值 / 冷却</th>
                      <th>状态</th>
                      <th style="text-align: right;">操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="fg in dnsFailoverList" :key="fg.id">
                      <td>
                        <div style="font-weight: 600;">{{ fg.name }}</div>
                        <div class="mono" style="font-size: 12px; color: var(--text-secondary);">
                          {{ fg.domain }} ({{ fg.record_type }} · TTL {{ fg.ttl }}s)
                        </div>
                      </td>
                      <td>
                        <span class="badge badge-info">{{ fg.provider.toUpperCase() }}</span>
                      </td>
                      <td style="font-size: 12px;">
                        <span class="badge badge-primary">主: {{ nodeNameById(fg.primary_node_id) }}</span>
                        <span
                          v-for="bid in parseAllowedIds(fg.backup_node_ids)"
                          :key="'fb-' + bid"
                          class="badge badge-neutral"
                          style="margin-left: 4px;"
                        >
                          备: {{ nodeNameById(bid) }}
                        </span>
                      </td>
                      <td>
                        <div v-if="fg.active_node_id" style="font-size: 12.5px; font-weight: 600;">
                          {{ nodeNameById(fg.active_node_id) }}
                          <span
                            v-if="fg.active_node_id !== fg.primary_node_id"
                            class="badge badge-warning"
                            style="margin-left: 4px;"
                          >
                            容灾接管中
                          </span>
                        </div>
                        <div class="mono" style="font-size: 11.5px; color: var(--text-muted);">
                          {{ fg.active_ip || '等待首次巡检同步' }} · 切换 {{ fg.switch_count || 0 }} 次
                        </div>
                        <div v-if="fg.last_error" style="font-size: 11px; color: var(--danger-text); margin-top: 2px;">
                          {{ fg.last_error }}
                        </div>
                      </td>
                      <td class="mono" style="font-size: 12px; color: var(--text-secondary);">
                        <div>离线 {{ fg.offline_threshold_sec }}s 切换</div>
                        <div style="font-size: 11px; color: var(--text-muted);">
                          冷却 {{ fg.cooldown_sec }}s · {{ fg.auto_failback ? '自动回切' : '保持接管' }}
                        </div>
                      </td>
                      <td>
                        <span class="badge" :class="fg.enabled ? 'badge-success' : 'badge-neutral'">
                          {{ fg.enabled ? '巡检中' : '已停用' }}
                        </span>
                      </td>
                      <td style="text-align: right; white-space: nowrap;">
                        <button
                          @click="reconcileFailoverGroup(fg)"
                          class="btn btn-soft btn-sm"
                          style="margin-right: 4px;"
                          :disabled="reconcilingFailoverId === fg.id"
                        >
                          {{ reconcilingFailoverId === fg.id ? '同步中...' : '立即巡检切换' }}
                        </button>
                        <button @click="openEditFailoverModal(fg)" class="btn btn-outline btn-sm" style="margin-right: 4px;">
                          编辑
                        </button>
                        <button @click="deleteFailoverGroup(fg)" class="btn btn-danger btn-sm">删除</button>
                      </td>
                    </tr>
                    <tr v-if="dnsFailoverList.length === 0">
                      <td colspan="7" style="padding: 0;">
                        <div class="empty-state" style="padding: 24px 16px;">
                          <div class="empty-state-title">暂无多入口 DNS 自动容灾组</div>
                          <div class="empty-state-desc">
                            点击右上角「+ 新增 DNS 容灾组」绑定主备入口节点，实现故障秒级 DNS 自动切换与恢复回切
                          </div>
                        </div>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          <!-- 角色管理 (仅管理员：角色决定可用哪些隧道) -->
          <div v-if="activeTab === 'roles' && isAdmin" style="display: flex; flex-direction: column; gap: 14px;">
            <div style="display: flex; justify-content: space-between; align-items: center; gap: 10px; flex-wrap: wrap;">
              <span style="font-size: 12.5px; color: var(--text-secondary);">
                角色决定了可以使用哪些隧道；套餐绑定角色后，分配了对应套餐与角色的用户即获得相应隧道的转发权限。
              </span>
              <button @click="openCreateRoleModal" class="btn btn-primary">+ 新增角色</button>
            </div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>角色名称</th>
                    <th>说明</th>
                    <th>可用隧道 (由角色决定)</th>
                    <th>绑定套餐数</th>
                    <th>关联用户数</th>
                    <th style="text-align: right;">操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="rg in rolesList" :key="rg.id">
                    <td style="font-weight: 600;">{{ rg.name }}</td>
                    <td style="color: var(--text-secondary);">{{ rg.description || '-' }}</td>
                    <td>
                      <span
                        v-for="tid in parseAllowedIds(rg.allowed_tunnels)"
                        :key="tid"
                        class="badge badge-primary"
                        style="margin-right: 4px;"
                      >
                        {{ getTunnelById(tid)?.name || '#' + tid }}
                      </span>
                      <span v-if="parseAllowedIds(rg.allowed_tunnels).length === 0" style="color: var(--text-muted);">
                        未分配隧道
                      </span>
                    </td>
                    <td>{{ rolePlanCountMap.get(rg.id) || 0 }} 个套餐</td>
                    <td>{{ roleUserCountMap.get(rg.id) || 0 }} 人</td>
                    <td style="text-align: right; white-space: nowrap;">
                      <button @click="openEditRoleModal(rg)" class="btn btn-soft btn-sm" style="margin-right: 4px;">
                        配置隧道
                      </button>
                      <button @click="deleteRoleGroup(rg)" class="btn btn-danger btn-sm">删除</button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- 用户管理 (仅管理员，分配套餐和角色) -->
          <div v-if="activeTab === 'users' && isAdmin" style="display: flex; flex-direction: column; gap: 14px;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
              <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                <input
                  v-model="userSearchQuery"
                  class="input"
                  style="width: 220px;"
                  placeholder="搜索用户邮箱 / ID"
                />
                <select v-model="userFilterPlanId" class="select" style="width: 145px;">
                  <option :value="-1">全部套餐</option>
                  <option :value="0">未绑定套餐</option>
                  <option v-for="p in plans" :key="p.id" :value="p.id">{{ p.name }}</option>
                </select>
                <select v-model="userFilterRoleId" class="select" style="width: 145px;">
                  <option :value="-1">全部角色</option>
                  <option v-for="rg in rolesList" :key="rg.id" :value="rg.id">{{ rg.name }}</option>
                </select>
                <select v-model="userFilterStatus" class="select" style="width: 135px;">
                  <option value="all">全部状态</option>
                  <option value="active">正常可用</option>
                  <option value="expired">套餐已过期</option>
                  <option value="over_quota">流量超额</option>
                  <option value="banned">已封禁</option>
                </select>
                <span style="font-size: 12px; color: var(--text-muted);">
                  共 {{ filteredUsersList.length }} / {{ usersList.length }} 人
                </span>
              </div>
              <button @click="openCreateUserModal" class="btn btn-primary">+ 新增用户</button>
            </div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>用户</th>
                    <th>账号类型</th>
                    <th>绑定套餐</th>
                    <th>所属角色</th>
                    <th>角色可用隧道</th>
                    <th>流量</th>
                    <th>规则 / 限速</th>
                    <th>到期时间</th>
                    <th>状态</th>
                    <th style="text-align: right;">操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="u in pagedUsersList" :key="u.id">
                    <td style="font-weight: 500;">{{ u.email }}</td>
                    <td>
                      <span class="badge" :class="u.role === 'admin' ? 'badge-purple' : 'badge-neutral'">
                        {{ u.role === 'admin' ? '管理员' : '普通用户' }}
                      </span>
                    </td>
                    <td>
                      <span v-if="u.role === 'admin'" style="color: var(--text-muted);">-</span>
                      <span v-else class="badge badge-neutral">{{ planNameById(u.plan_id) }}</span>
                    </td>
                    <td>
                      <span v-if="u.role === 'admin'" class="badge badge-purple">全权限管理员</span>
                      <span v-else class="badge badge-primary">{{ roleNameById(u.role_group_id) }}</span>
                    </td>
                    <td>
                      <span v-if="u.role === 'admin' || u.allowed_tunnels === '*'" class="badge badge-purple">
                        全部隧道
                      </span>
                      <template v-else>
                        <span
                          v-for="tid in allowedTunnelIdsForUser(u)"
                          :key="tid"
                          class="badge badge-neutral"
                          style="margin-right: 4px;"
                        >
                          {{ getTunnelById(tid)?.name || '#' + tid }}
                        </span>
                        <span v-if="allowedTunnelIdsForUser(u).length === 0" style="color: var(--text-muted);">
                          未分配
                        </span>
                      </template>
                    </td>
                    <td>{{ formatBytes(u.used_bytes) }} / {{ formatBytes(u.quota_bytes) }}</td>
                    <td>{{ u.max_rules }} 条 · {{ u.speed_mbps }} Mbps</td>
                    <td style="white-space: nowrap;">
                      <span v-if="u.role === 'admin'" style="color: var(--text-muted);">永久</span>
                      <span v-else :style="{ color: isUserExpired(u) ? 'var(--danger-text)' : 'inherit' }">
                        {{ formatDateDisplay(u.expire_at) }}{{ isUserExpired(u) ? ' (已过期)' : '' }}
                      </span>
                    </td>
                    <td>
                      <span class="badge" :class="u.status === 'active' ? 'badge-success' : 'badge-danger'">
                        <span class="dot"></span> {{ u.status === 'active' ? '正常' : '已封禁' }}
                      </span>
                    </td>
                    <td style="text-align: right; white-space: nowrap;">
                      <button @click="openEditUserModal(u)" class="btn btn-soft btn-sm" style="margin-right: 4px;">
                        分配套餐/角色
                      </button>
                      <button
                        @click="resetUserSubscriptionAdmin(u)"
                        class="btn btn-outline btn-sm"
                        style="margin-right: 4px;"
                        title="按绑定套餐刷新到期时间、清零已用流量并恢复超额暂停规则"
                      >
                        重置订阅
                      </button>
                      <button @click="resetUserTraffic(u)" class="btn btn-outline btn-sm" style="margin-right: 4px;">
                        重置流量
                      </button>
                      <button
                        @click="openAdminResetPwdModal(u)"
                        class="btn btn-outline btn-sm"
                        style="margin-right: 4px;"
                      >
                        重置密码
                      </button>
                      <button
                        @click="resetUserSubTokenAdmin(u)"
                        class="btn btn-outline btn-sm"
                        style="margin-right: 4px;"
                        title="重新生成订阅 Token，使旧订阅链接失效"
                      >
                        重置订阅链接
                      </button>
                      <button
                        v-if="u.role !== 'admin'"
                        @click="toggleUserBan(u)"
                        class="btn btn-sm"
                        :class="u.status === 'active' ? 'btn-danger' : 'btn-outline'"
                        style="margin-right: 4px;"
                      >
                        {{ u.status === 'active' ? '封禁' : '解封' }}
                      </button>
                      <button
                        v-if="u.role !== 'admin'"
                        @click="deleteUserAccount(u)"
                        class="btn btn-danger btn-sm"
                      >
                        删除
                      </button>
                    </td>
                  </tr>
                  <tr v-if="filteredUsersList.length === 0">
                    <td colspan="10" style="padding: 0;">
                      <div class="empty-state">
                        <div class="empty-state-title">未找到符合条件的用户</div>
                        <div class="empty-state-desc">请尝试清空筛选条件，或点击右上角「+ 新增用户」创建账号</div>
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
              <div v-if="filteredUsersList.length > 0" class="pagination-bar">
                <span>第 {{ usersPage }} / {{ usersTotalPages }} 页 · 共 {{ filteredUsersList.length }} 位用户</span>
                <div class="pagination-controls">
                  <select v-model.number="usersPageSize" class="select pagination-select">
                    <option :value="20">20 条/页</option>
                    <option :value="50">50 条/页</option>
                    <option :value="100">100 条/页</option>
                  </select>
                  <button class="btn btn-outline btn-sm" :disabled="usersPage <= 1" @click="usersPage--">上一页</button>
                  <button class="btn btn-outline btn-sm" :disabled="usersPage >= usersTotalPages" @click="usersPage++">下一页</button>
                </div>
              </div>
            </div>
          </div>

          <!-- 套餐管理 (管理员可配置套餐并绑定角色；普通用户可购买升级套餐与角色) -->
          <div v-if="activeTab === 'store'" style="display: flex; flex-direction: column; gap: 16px;">
            <div
              class="card"
              style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap;"
            >
              <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap; font-size: 13px;">
                <span>
                  当前套餐：<strong>{{ isAdmin ? '管理员账号' : planNameById(user?.plan_id) }}</strong>
                </span>
                <span style="color: var(--text-secondary);">
                  已用流量：{{ formatBytes(user?.used_bytes || 0) }} / {{ formatBytes(user?.quota_bytes || 0) }}
                </span>
                <span v-if="!isAdmin" style="color: var(--text-secondary);">
                  到期时间：{{ formatDateDisplay(user?.expire_at) }}
                </span>
                <span style="color: var(--text-secondary);">
                  账户余额：<strong>¥{{ ((user?.balance_cents || 0) / 100).toFixed(2) }}</strong>
                </span>
              </div>
              <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                <button @click="openRechargeModal" class="btn btn-primary btn-sm">+ 在线充值余额</button>
                <button
                  v-if="currentBoundPlan && currentBoundPlan.price_cents > 0"
                  @click="handleResetSubscription"
                  class="btn btn-soft btn-sm"
                >
                  提前重置当月流量 / 周期 (¥{{ (currentBoundPlan.price_cents / 100).toFixed(2) }})
                </button>
                <button @click="handleResetSubToken" class="btn btn-outline btn-sm">重置订阅链接</button>
              </div>
            </div>

            <div style="display: flex; justify-content: space-between; align-items: center; gap: 10px; flex-wrap: wrap;">
              <div style="display: flex; align-items: center; gap: 8px;">
                <input
                  v-model="redeemInput"
                  class="input"
                  style="width: 240px;"
                  placeholder="输入套餐 / 充值 / 流量兑换码"
                  @keyup.enter="handleRedeem"
                />
                <button @click="handleRedeem" class="btn btn-soft">立即核销兑换码</button>
              </div>
              <div v-if="isAdmin" style="display: flex; gap: 8px; flex-wrap: wrap;">
                <button @click="openRedeemGenModal" class="btn btn-soft">+ 批量生成卡密</button>
                <button @click="openCreatePlanModal" class="btn btn-primary">+ 新增套餐</button>
              </div>
            </div>

            <!-- 管理员视角：套餐列表与绑定角色管理表 -->
            <div v-if="isAdmin" class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>套餐名称</th>
                    <th>绑定角色</th>
                    <th>角色可用隧道</th>
                    <th>价格 / 周期</th>
                    <th>流量配额</th>
                    <th>规则数 / 限速</th>
                    <th style="text-align: right;">操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="plan in plans" :key="plan.id">
                    <td style="font-weight: 600;">{{ plan.name }}</td>
                    <td>
                      <span class="badge badge-purple">{{ roleNameById(plan.role_group_id) }}</span>
                    </td>
                    <td>
                      <span
                        v-for="tid in parseAllowedIds(getRoleById(plan.role_group_id)?.allowed_tunnels || plan.allowed_tunnels)"
                        :key="tid"
                        class="badge badge-primary"
                        style="margin-right: 4px;"
                      >
                        {{ getTunnelById(tid)?.name || '#' + tid }}
                      </span>
                    </td>
                    <td>¥{{ (plan.price_cents / 100).toFixed(2) }} / {{ plan.duration_days }}天</td>
                    <td>{{ formatBytes(plan.quota_bytes) }}</td>
                    <td>{{ plan.max_rules }} 条 · {{ plan.speed_mbps }} Mbps</td>
                    <td style="text-align: right; white-space: nowrap;">
                      <button @click="openEditPlanModal(plan)" class="btn btn-soft btn-sm" style="margin-right: 4px;">
                        编辑套餐
                      </button>
                      <button @click="deletePlanItem(plan)" class="btn btn-danger btn-sm">删除</button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <!-- 管理员视角：兑换码 / 卡密管理中心 -->
            <div v-if="isAdmin" class="card" style="display: flex; flex-direction: column; gap: 12px;">
              <div style="display: flex; justify-content: space-between; align-items: center; gap: 10px; flex-wrap: wrap;">
                <div>
                  <div style="font-weight: 600; font-size: 14px;">兑换码 / 卡密管理中心</div>
                  <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">
                    支持生成套餐激活卡、余额充值卡与流量时长叠加卡，核销后自动发放权益
                  </div>
                </div>
                <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                  <input
                    v-model="redeemSearchKeyword"
                    class="input"
                    style="width: 190px; height: 32px; font-size: 12.5px;"
                    placeholder="搜索卡密 / 备注 / 核销邮箱"
                  />
                  <select v-model="redeemFilterStatus" class="select" style="width: 120px; height: 32px; font-size: 12.5px;">
                    <option value="all">全部状态</option>
                    <option value="unused">未使用</option>
                    <option value="used">已核销</option>
                  </select>
                  <button @click="copyAllUnusedRedeemCodes" class="btn btn-soft btn-sm">复制未用卡密</button>
                  <button @click="clearUsedRedeemCodes" class="btn btn-outline btn-sm">清理已核销</button>
                  <button @click="openRedeemGenModal" class="btn btn-primary btn-sm">+ 生成卡密</button>
                </div>
              </div>

              <div class="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>卡密 (点击复制)</th>
                      <th>卡密类型 / 权益内容</th>
                      <th>备注</th>
                      <th>状态 / 核销人</th>
                      <th style="text-align: right;">操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="rc in pagedRedeemCodes" :key="rc.id">
                      <td>
                        <button
                          @click="copyConnectAddr(rc.code)"
                          class="btn btn-soft btn-sm mono"
                          style="font-weight: 600;"
                        >
                          {{ rc.code }}
                        </button>
                      </td>
                      <td style="font-size: 12.5px;">
                        <span v-if="rc.plan_id > 0" class="badge badge-purple" style="margin-right: 6px;">
                          套餐: {{ rc.plan_name || planNameById(rc.plan_id) }}
                        </span>
                        <span v-if="rc.balance_cents > 0" class="badge badge-success" style="margin-right: 6px;">
                          余额 +¥{{ (rc.balance_cents / 100).toFixed(2) }}
                        </span>
                        <span v-if="rc.quota_bytes > 0" style="margin-right: 6px;">
                          流量 +{{ formatBytes(rc.quota_bytes) }}
                        </span>
                        <span v-if="rc.duration_days > 0" style="color: var(--text-secondary);">
                          时长 +{{ rc.duration_days }}天
                        </span>
                      </td>
                      <td style="font-size: 12.5px; color: var(--text-secondary);">{{ rc.note || '-' }}</td>
                      <td style="font-size: 12.5px;">
                        <span v-if="rc.used_by === 0" class="badge badge-success">未使用</span>
                        <div v-else style="display: flex; flex-direction: column; gap: 2px;">
                          <span class="badge badge-neutral">已核销</span>
                          <span style="font-size: 11.5px; color: var(--text-muted);">
                            {{ rc.used_by_email || '#' + rc.used_by }} ({{ formatDateDisplay(rc.used_at) }})
                          </span>
                        </div>
                      </td>
                      <td style="text-align: right;">
                        <button @click="deleteRedeemCodeItem(rc)" class="btn btn-danger btn-sm">删除</button>
                      </td>
                    </tr>
                    <tr v-if="filteredRedeemCodes.length === 0">
                      <td colspan="5" style="padding: 0;">
                        <div class="empty-state">
                          <div class="empty-state-title">暂无符合条件的兑换码记录</div>
                          <div class="empty-state-desc">可点击右上角「+ 生成卡密」批量创建套餐卡、充值卡或流量卡</div>
                        </div>
                      </td>
                    </tr>
                  </tbody>
                </table>
                <div v-if="filteredRedeemCodes.length > 0" class="pagination-bar">
                  <span>第 {{ redeemPage }} / {{ redeemTotalPages }} 页 · 共 {{ filteredRedeemCodes.length }} 条卡密</span>
                  <div class="pagination-controls">
                    <select v-model.number="redeemPageSize" class="select pagination-select">
                      <option :value="20">20 条/页</option>
                      <option :value="50">50 条/页</option>
                      <option :value="100">100 条/页</option>
                    </select>
                    <button class="btn btn-outline btn-sm" :disabled="redeemPage <= 1" @click="redeemPage--">上一页</button>
                    <button class="btn btn-outline btn-sm" :disabled="redeemPage >= redeemTotalPages" @click="redeemPage++">下一页</button>
                  </div>
                </div>
              </div>
            </div>

            <!-- 管理员视角：优惠券 / 折扣码管理中心 -->
            <div v-if="isAdmin" class="card" style="display: flex; flex-direction: column; gap: 12px;">
              <div style="display: flex; justify-content: space-between; align-items: center; gap: 10px; flex-wrap: wrap;">
                <div>
                  <div style="font-weight: 600; font-size: 14px;">优惠券 / 折扣码管理中心</div>
                  <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">
                    支持百分比折扣券与固定满减券、限定套餐、有效期、总次数与单用户限用次数，结账时实时试算抵扣
                  </div>
                </div>
                <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                  <input
                    v-model="couponSearchQuery"
                    class="input"
                    style="width: 190px; height: 32px; font-size: 12.5px;"
                    placeholder="搜索优惠券码 / 名称"
                  />
                  <button @click="openCreateCouponModal" class="btn btn-primary btn-sm">+ 新增优惠券</button>
                </div>
              </div>

              <div class="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>优惠券码 (点击复制)</th>
                      <th>名称 / 抵扣规则</th>
                      <th>适用套餐</th>
                      <th>有效期</th>
                      <th>已用 / 限额</th>
                      <th>状态</th>
                      <th style="text-align: right;">操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="cp in pagedCoupons" :key="cp.id">
                      <td>
                        <button
                          @click="copyConnectAddr(cp.code)"
                          class="btn btn-soft btn-sm mono"
                          style="font-weight: 600;"
                        >
                          {{ cp.code }}
                        </button>
                      </td>
                      <td style="font-size: 12.5px;">
                        <div style="font-weight: 600;">{{ cp.name }}</div>
                        <div style="color: var(--text-secondary); margin-top: 2px;">
                          <span v-if="cp.type === 'percent'" class="badge badge-info" style="margin-right: 6px;">
                            减免 {{ cp.value }}% ({{ ((100 - cp.value) / 10).toFixed(1).replace(/\.0$/, '') }}折)
                          </span>
                          <span v-else class="badge badge-success" style="margin-right: 6px;">
                            立减 ¥{{ (cp.value / 100).toFixed(2) }}
                          </span>
                          <span v-if="cp.min_spend_cents > 0" style="font-size: 11.5px;">
                            满 ¥{{ (cp.min_spend_cents / 100).toFixed(2) }} 可用
                          </span>
                          <span v-if="cp.type === 'percent' && cp.max_discount_cents > 0" style="font-size: 11.5px; margin-left: 6px;">
                            封顶 ¥{{ (cp.max_discount_cents / 100).toFixed(2) }}
                          </span>
                        </div>
                      </td>
                      <td style="font-size: 12px;">
                        <span v-if="!cp.allowed_plan_ids" class="badge badge-neutral">全场套餐通用</span>
                        <span
                          v-for="pid in parseAllowedIds(cp.allowed_plan_ids)"
                          :key="pid"
                          class="badge badge-purple"
                          style="margin-right: 4px;"
                        >
                          {{ planNameById(pid) }}
                        </span>
                      </td>
                      <td class="mono" style="font-size: 11.5px; color: var(--text-secondary);">
                        <div v-if="cp.starts_at || cp.ends_at">
                          {{ formatDateDisplay(cp.starts_at) }} ~ {{ formatDateDisplay(cp.ends_at) }}
                        </div>
                        <span v-else>长期有效</span>
                      </td>
                      <td class="mono" style="font-size: 12px;">
                        <div>{{ cp.used_count }} / {{ cp.max_uses > 0 ? cp.max_uses : '∞' }}</div>
                        <div style="font-size: 11px; color: var(--text-muted);">
                          每人限 {{ cp.per_user_limit > 0 ? cp.per_user_limit + ' 次' : '不限' }}
                        </div>
                      </td>
                      <td>
                        <span class="badge" :class="cp.active ? 'badge-success' : 'badge-neutral'">
                          {{ cp.active ? '生效中' : '已停用' }}
                        </span>
                      </td>
                      <td style="text-align: right; white-space: nowrap;">
                        <button @click="toggleCouponActive(cp)" class="btn btn-outline btn-sm" style="margin-right: 4px;">
                          {{ cp.active ? '停用' : '启用' }}
                        </button>
                        <button @click="openEditCouponModal(cp)" class="btn btn-soft btn-sm" style="margin-right: 4px;">
                          编辑
                        </button>
                        <button @click="deleteCouponItem(cp)" class="btn btn-danger btn-sm">删除</button>
                      </td>
                    </tr>
                    <tr v-if="filteredCoupons.length === 0">
                      <td colspan="7" style="padding: 0;">
                        <div class="empty-state">
                          <div class="empty-state-title">暂无优惠券与折扣码配置</div>
                          <div class="empty-state-desc">点击右上角「+ 新增优惠券」可发放百分比折扣券或满减促销码</div>
                        </div>
                      </td>
                    </tr>
                  </tbody>
                </table>
                <div v-if="filteredCoupons.length > 0" class="pagination-bar">
                  <span>第 {{ couponsPage }} / {{ couponsTotalPages }} 页 · 共 {{ filteredCoupons.length }} 张优惠券</span>
                  <div class="pagination-controls">
                    <select v-model.number="couponsPageSize" class="select pagination-select">
                      <option :value="20">20 条/页</option>
                      <option :value="50">50 条/页</option>
                    </select>
                    <button class="btn btn-outline btn-sm" :disabled="couponsPage <= 1" @click="couponsPage--">上一页</button>
                    <button class="btn btn-outline btn-sm" :disabled="couponsPage >= couponsTotalPages" @click="couponsPage++">下一页</button>
                  </div>
                </div>
              </div>
            </div>

            <!-- 套餐商城卡片展示 -->
            <div class="grid-2">
              <div
                v-for="plan in plans"
                :key="plan.id"
                class="card"
                style="display: flex; flex-direction: column; justify-content: space-between; gap: 14px;"
              >
                <div>
                  <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                      <span style="font-weight: 600; font-size: 15px;">{{ plan.name }}</span>
                      <span class="badge badge-purple">{{ roleNameById(plan.role_group_id) }}</span>
                    </div>
                    <span style="font-weight: 600; color: var(--primary-text);">
                      ¥{{ (plan.price_cents / 100).toFixed(2) }} / {{ plan.duration_days }}天
                    </span>
                  </div>
                  <div
                    style="margin-top: 10px; font-size: 13px; color: var(--text-secondary); display: flex; gap: 16px;"
                  >
                    <span>流量 {{ formatBytes(plan.quota_bytes) }}</span>
                    <span>规则 {{ plan.max_rules }} 条</span>
                    <span>限速 {{ plan.speed_mbps }} Mbps</span>
                  </div>
                  <div style="margin-top: 10px; display: flex; align-items: center; flex-wrap: wrap; gap: 6px; font-size: 12px;">
                    <span style="color: var(--text-muted);">可用隧道：</span>
                    <span
                      v-for="tid in parseAllowedIds(getRoleById(plan.role_group_id)?.allowed_tunnels || plan.allowed_tunnels)"
                      :key="tid"
                      class="badge badge-primary"
                    >
                      {{ getTunnelById(tid)?.name || '#' + tid }}
                    </span>
                  </div>
                </div>
                <button @click="handleBuyPlan(plan.id)" class="btn btn-primary" style="width: 100%;">
                  {{ user?.plan_id === plan.id ? '续费 / 重新激活该套餐（支持优惠券）' : '购买并激活套餐（支持优惠券）' }}
                </button>
              </div>
            </div>

            <!-- 账单与订单明细 -->
            <div class="card" style="display: flex; flex-direction: column; gap: 12px;">
              <div style="display: flex; justify-content: space-between; align-items: center; gap: 10px; flex-wrap: wrap;">
                <div>
                  <div style="font-weight: 600; font-size: 14px;">{{ isAdmin ? '全站账单与充值订单明细' : '我的账单与充值记录' }}</div>
                  <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">
                    自动记录在线充值、套餐购买、周期重置、优惠券抵扣与佣金划转流水（超时未支付订单自动关闭）
                  </div>
                </div>
                <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                  <input
                    v-model="orderSearchQuery"
                    class="input"
                    style="width: 190px; height: 32px; font-size: 12.5px;"
                    placeholder="搜索订单号 / 邮箱 / 套餐"
                  />
                  <select v-model="orderFilterStatus" class="select" style="width: 116px; height: 32px; font-size: 12.5px;">
                    <option value="all">全部状态</option>
                    <option value="paid">已入账</option>
                    <option value="pending">待支付</option>
                    <option value="cancelled">已取消</option>
                  </select>
                  <button @click="openRechargeModal" class="btn btn-soft btn-sm">+ 创建充值订单</button>
                </div>
              </div>

              <div class="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>订单号</th>
                      <th v-if="isAdmin">用户</th>
                      <th>类型</th>
                      <th>说明 / 套餐</th>
                      <th>金额</th>
                      <th>通道</th>
                      <th>状态</th>
                      <th>时间</th>
                      <th v-if="isAdmin" style="text-align: right;">操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="ord in pagedOrders" :key="ord.id">
                      <td class="mono" style="font-size: 12px;">{{ ord.order_no }}</td>
                      <td v-if="isAdmin" style="font-size: 12.5px;">{{ ord.user_email || '#' + ord.user_id }}</td>
                      <td>
                        <span class="badge badge-neutral">{{ orderTypeLabel(ord.type) }}</span>
                      </td>
                      <td style="font-size: 12.5px;">
                        <span>{{ ord.plan_name || '-' }}</span>
                        <span
                          v-if="ord.coupon_code && (ord.discount_cents || 0) > 0"
                          class="badge badge-success mono"
                          style="margin-left: 6px;"
                        >
                          {{ ord.coupon_code }} -¥{{ ((ord.discount_cents || 0) / 100).toFixed(2) }}
                        </span>
                      </td>
                      <td class="mono" style="font-weight: 600;">¥{{ ((ord.amount_cents || 0) / 100).toFixed(2) }}</td>
                      <td style="font-size: 12px; color: var(--text-secondary);">{{ ord.gateway.toUpperCase() }}</td>
                      <td>
                        <span
                          class="badge"
                          :class="ord.status === 'paid' ? 'badge-success' : ord.status === 'pending' ? 'badge-warning' : 'badge-neutral'"
                        >
                          {{ ord.status === 'paid' ? '已入账' : ord.status === 'pending' ? '待支付' : '已关闭' }}
                        </span>
                      </td>
                      <td class="mono" style="font-size: 12px; color: var(--text-muted);">{{ formatDateDisplay(ord.created_at) }}</td>
                      <td v-if="isAdmin" style="text-align: right;">
                        <button
                          v-if="ord.type === 'recharge' && ord.status === 'pending'"
                          @click="confirmOrderAdmin(ord)"
                          class="btn btn-primary btn-sm"
                        >
                          确认入账
                        </button>
                        <span v-else style="color: var(--text-muted); font-size: 12px;">-</span>
                      </td>
                    </tr>
                    <tr v-if="filteredOrders.length === 0">
                      <td :colspan="isAdmin ? 9 : 8" style="padding: 0;">
                        <div class="empty-state">
                          <div class="empty-state-title">暂无匹配的账单与订单记录</div>
                          <div class="empty-state-desc">购买套餐、在线充值或核销兑换码后会自动生成账单流水</div>
                        </div>
                      </td>
                    </tr>
                  </tbody>
                </table>
                <div v-if="filteredOrders.length > 0" class="pagination-bar">
                  <span>第 {{ ordersPage }} / {{ ordersTotalPages }} 页 · 共 {{ filteredOrders.length }} 笔订单</span>
                  <div class="pagination-controls">
                    <select v-model.number="ordersPageSize" class="select pagination-select">
                      <option :value="20">20 条/页</option>
                      <option :value="50">50 条/页</option>
                      <option :value="100">100 条/页</option>
                    </select>
                    <button class="btn btn-outline btn-sm" :disabled="ordersPage <= 1" @click="ordersPage--">上一页</button>
                    <button class="btn btn-outline btn-sm" :disabled="ordersPage >= ordersTotalPages" @click="ordersPage++">下一页</button>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- 推广返利 / 邀请分销中心 (所有用户均可生成邀请链接与管理佣金；管理员可审核全站提现) -->
          <div v-if="activeTab === 'affiliate'" style="display: flex; flex-direction: column; gap: 16px;">
            <div
              class="card"
              style="display: flex; justify-content: space-between; align-items: center; gap: 14px; flex-wrap: wrap;"
            >
              <div style="display: flex; flex-direction: column; gap: 6px; min-width: 240px;">
                <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                  <span style="font-weight: 700; font-size: 15px;">专属邀请码与推广链接</span>
                  <span class="badge" :class="affiliateOverview?.enabled !== false ? 'badge-success' : 'badge-neutral'">
                    {{ affiliateOverview?.enabled !== false ? '返佣计划开启中' : '返佣计划已暂停' }}
                  </span>
                </div>
                <div style="font-size: 12.5px; color: var(--text-secondary);">
                  好友通过您的推广链接或邀请码完成注册后，充值或购买套餐将自动按
                  <strong>{{ affiliateOverview?.commission_rate ?? siteConfig.affiliate_commission_rate ?? 10 }}%</strong>
                  实时结算佣金至您的推广账户。
                </div>
                <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 4px;">
                  <button
                    @click="copyConnectAddr(affiliateOverview?.invite_code || user?.invite_code || '')"
                    class="copy-pill"
                  >
                    邀请码：{{ affiliateOverview?.invite_code || user?.invite_code || '-' }}
                  </button>
                  <button
                    v-if="affiliateOverview?.invite_url"
                    @click="copyConnectAddr(affiliateOverview.invite_url)"
                    class="btn btn-soft btn-sm"
                  >
                    复制专属推广链接
                  </button>
                </div>
              </div>

              <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                <button
                  @click="handleTransferCommission"
                  class="btn btn-primary"
                  :disabled="(affiliateOverview?.commission_balance_cents || 0) <= 0"
                >
                  一键划转至账户余额
                </button>
                <button
                  @click="openWithdrawModal"
                  class="btn btn-outline"
                  :disabled="(affiliateOverview?.commission_balance_cents || 0) < (affiliateOverview?.min_withdraw_cents || 1000)"
                >
                  申请佣金提现 (满 ¥{{ ((affiliateOverview?.min_withdraw_cents || 1000) / 100).toFixed(0) }})
                </button>
              </div>
            </div>

            <div class="grid-4">
              <div class="card">
                <div class="metric-label">当前返佣比例</div>
                <div class="metric-value">{{ affiliateOverview?.commission_rate ?? siteConfig.affiliate_commission_rate ?? 10 }}%</div>
                <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">充值与套餐消费自动结算</div>
              </div>
              <div class="card">
                <div class="metric-label">累计邀请用户</div>
                <div class="metric-value">{{ affiliateOverview?.invited_count ?? 0 }}</div>
                <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">已绑定永久邀请返佣关系</div>
              </div>
              <div class="card">
                <div class="metric-label">累计获得佣金</div>
                <div class="metric-value">¥{{ ((affiliateOverview?.total_commission_cents || 0) / 100).toFixed(2) }}</div>
                <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">历史结算佣金总额</div>
              </div>
              <div class="card">
                <div class="metric-label">可用佣金余额</div>
                <div class="metric-value" style="color: var(--primary-text);">
                  ¥{{ ((affiliateOverview?.commission_balance_cents || 0) / 100).toFixed(2) }}
                </div>
                <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
                  提现审核冻结：¥{{ ((affiliateOverview?.pending_withdraw_cents || 0) / 100).toFixed(2) }}
                </div>
              </div>
            </div>

            <!-- 管理员视角：全站佣金提现审核工作台 -->
            <div v-if="isAdmin" class="card" style="display: flex; flex-direction: column; gap: 12px;">
              <div style="display: flex; justify-content: space-between; align-items: center; gap: 10px; flex-wrap: wrap;">
                <div>
                  <div style="font-weight: 600; font-size: 14px;">全站推广佣金提现审核台（管理员）</div>
                  <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">
                    审核通过后标记已打款；驳回申请将自动把冻结佣金原路退回申请人可用佣金余额
                  </div>
                </div>
                <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                  <input
                    v-model="withdrawSearchQuery"
                    class="input"
                    style="width: 190px; height: 32px; font-size: 12.5px;"
                    placeholder="搜索提现单号 / 邮箱 / 收款账号"
                  />
                  <select v-model="withdrawFilterStatus" class="select" style="width: 120px; height: 32px; font-size: 12.5px;">
                    <option value="all">全部状态</option>
                    <option value="pending">待审核</option>
                    <option value="approved">已打款</option>
                    <option value="rejected">已驳回</option>
                  </select>
                </div>
              </div>

              <div class="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>提现单号</th>
                      <th>申请人</th>
                      <th>提现金额</th>
                      <th>收款方式 / 账号</th>
                      <th>状态 / 备注</th>
                      <th>申请时间</th>
                      <th style="text-align: right;">审核操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="wd in filteredAdminWithdrawals" :key="wd.id">
                      <td class="mono" style="font-size: 12px;">{{ wd.withdraw_no }}</td>
                      <td style="font-size: 12.5px;">{{ wd.user_email }}</td>
                      <td class="mono" style="font-weight: 700;">¥{{ (wd.amount_cents / 100).toFixed(2) }}</td>
                      <td style="font-size: 12px;">
                        <span class="badge badge-info" style="margin-right: 6px;">{{ withdrawMethodLabel(wd.method) }}</span>
                        <span class="mono">{{ wd.account }}</span>
                        <span v-if="wd.real_name" style="color: var(--text-muted); margin-left: 6px;">({{ wd.real_name }})</span>
                      </td>
                      <td style="font-size: 12px;">
                        <span
                          class="badge"
                          :class="wd.status === 'approved' ? 'badge-success' : wd.status === 'pending' ? 'badge-warning' : 'badge-danger'"
                        >
                          {{ wd.status === 'approved' ? '已打款' : wd.status === 'pending' ? '待审核' : '已驳回' }}
                        </span>
                        <span v-if="wd.admin_remark" style="color: var(--text-muted); margin-left: 6px;">{{ wd.admin_remark }}</span>
                      </td>
                      <td class="mono" style="font-size: 12px; color: var(--text-muted);">{{ formatDateTimeDisplay(wd.created_at) }}</td>
                      <td style="text-align: right; white-space: nowrap;">
                        <template v-if="wd.status === 'pending'">
                          <button @click="reviewWithdrawalAdmin(wd, 'approve')" class="btn btn-primary btn-sm" style="margin-right: 4px;">
                            通过打款
                          </button>
                          <button @click="reviewWithdrawalAdmin(wd, 'reject')" class="btn btn-danger btn-sm">
                            驳回退回
                          </button>
                        </template>
                        <span v-else style="font-size: 12px; color: var(--text-muted);">已处理</span>
                      </td>
                    </tr>
                    <tr v-if="filteredAdminWithdrawals.length === 0">
                      <td colspan="7" style="padding: 0;">
                        <div class="empty-state">
                          <div class="empty-state-title">暂无匹配的提现申请记录</div>
                          <div class="empty-state-desc">用户发起推广佣金提现申请后将在此处展示待审核工单</div>
                        </div>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <div class="grid-2">
              <!-- 返佣结算明细 -->
              <div class="card" style="display: flex; flex-direction: column; gap: 10px;">
                <div style="font-weight: 600; font-size: 14px;">我的返佣结算流水</div>
                <div class="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>受邀用户</th>
                        <th>触发场景</th>
                        <th>实付基数</th>
                        <th>返佣入账</th>
                        <th>时间</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr v-for="cm in (affiliateOverview?.commissions || [])" :key="cm.id">
                        <td class="mono" style="font-size: 12px;">{{ cm.invitee_email }}</td>
                        <td>
                          <span class="badge badge-primary">{{ affiliateSceneLabel(cm.scene) }}</span>
                        </td>
                        <td class="mono">¥{{ (cm.base_amount_cents / 100).toFixed(2) }}</td>
                        <td class="mono" style="font-weight: 700; color: var(--success-text);">
                          +¥{{ (cm.commission_cents / 100).toFixed(2) }} ({{ cm.rate_percent }}%)
                        </td>
                        <td class="mono" style="font-size: 11.5px; color: var(--text-muted);">
                          {{ formatDateTimeDisplay(cm.created_at) }}
                        </td>
                      </tr>
                      <tr v-if="!(affiliateOverview?.commissions?.length)">
                        <td colspan="5" style="padding: 0;">
                          <div class="empty-state" style="padding: 24px 14px;">
                            <div class="empty-state-title">暂无返佣结算记录</div>
                            <div class="empty-state-desc">复制上方专属推广链接邀请好友注册消费后自动结算</div>
                          </div>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              <!-- 我的提现申请记录 -->
              <div class="card" style="display: flex; flex-direction: column; gap: 10px;">
                <div style="font-weight: 600; font-size: 14px;">我的佣金提现记录</div>
                <div class="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>单号</th>
                        <th>金额</th>
                        <th>收款方式</th>
                        <th>状态 / 备注</th>
                        <th>时间</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr v-for="wd in (affiliateOverview?.withdrawals || [])" :key="wd.id">
                        <td class="mono" style="font-size: 12px;">{{ wd.withdraw_no }}</td>
                        <td class="mono" style="font-weight: 600;">¥{{ (wd.amount_cents / 100).toFixed(2) }}</td>
                        <td style="font-size: 12px;">{{ withdrawMethodLabel(wd.method) }}</td>
                        <td style="font-size: 12px;">
                          <span
                            class="badge"
                            :class="wd.status === 'approved' ? 'badge-success' : wd.status === 'pending' ? 'badge-warning' : 'badge-danger'"
                          >
                            {{ wd.status === 'approved' ? '已打款' : wd.status === 'pending' ? '审核中' : '已驳回退回' }}
                          </span>
                          <div v-if="wd.admin_remark" style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">
                            {{ wd.admin_remark }}
                          </div>
                        </td>
                        <td class="mono" style="font-size: 11.5px; color: var(--text-muted);">
                          {{ formatDateTimeDisplay(wd.created_at) }}
                        </td>
                      </tr>
                      <tr v-if="!(affiliateOverview?.withdrawals?.length)">
                        <td colspan="5" style="padding: 0;">
                          <div class="empty-state" style="padding: 24px 14px;">
                            <div class="empty-state-title">暂无提现申请记录</div>
                            <div class="empty-state-desc">可将佣金一键零损耗划转至账户余额，或满额申请提现</div>
                          </div>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>

          <!-- 工单客服中心 (支持关联转发规则、对话式追问回复、后台处理流转与 Telegram/Webhook 联动提醒) -->
          <div v-if="activeTab === 'tickets'" style="display: flex; flex-direction: column; gap: 16px;">
            <div
              class="card"
              style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap;"
            >
              <div>
                <div style="font-weight: 600; font-size: 14.5px;">
                  {{ isAdmin ? '全站客服工单调度台' : '我的技术支持与客服工单' }}
                </div>
                <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">
                  {{ isAdmin ? '支持查看用户关联转发规则、对话回复、调整优先级与结单关闭' : '遇到线路波动、转发规则排障或账单问题可随时提交工单跟进' }}
                </div>
              </div>

              <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                <input
                  v-model="ticketSearchQuery"
                  class="input"
                  style="width: 190px; height: 32px; font-size: 12.5px;"
                  placeholder="搜索工单号 / 标题 / 规则"
                />
                <select v-model="ticketFilterCategory" class="select" style="width: 124px; height: 32px; font-size: 12.5px;">
                  <option value="all">全部分类</option>
                  <option value="network">线路与网络</option>
                  <option value="rule">转发规则</option>
                  <option value="billing">账单与支付</option>
                  <option value="account">账号与权限</option>
                  <option value="general">综合咨询</option>
                </select>
                <select v-model="ticketFilterStatus" class="select" style="width: 122px; height: 32px; font-size: 12.5px;">
                  <option value="all">全部状态</option>
                  <option value="open">待受理</option>
                  <option value="customer_reply">用户追问中</option>
                  <option value="answered">客服已回复</option>
                  <option value="closed">已结单</option>
                </select>
                <button @click="openCreateTicketModal" class="btn btn-primary btn-sm">+ 提交新工单</button>
              </div>
            </div>

            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>工单号</th>
                    <th v-if="isAdmin">提交用户</th>
                    <th>工单标题 / 关联规则</th>
                    <th>分类</th>
                    <th>优先级</th>
                    <th>状态</th>
                    <th>最近更新</th>
                    <th style="text-align: right;">操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="tk in pagedTickets" :key="tk.id">
                    <td class="mono" style="font-size: 12px;">{{ tk.ticket_no }}</td>
                    <td v-if="isAdmin" style="font-size: 12.5px;">{{ tk.user_email }}</td>
                    <td>
                      <div style="font-weight: 600; font-size: 13px;">{{ tk.subject }}</div>
                      <div v-if="tk.rule_name" style="margin-top: 3px;">
                        <span class="badge badge-primary mono" style="font-size: 11px;">关联规则: {{ tk.rule_name }}</span>
                      </div>
                    </td>
                    <td>
                      <span class="badge badge-neutral">{{ ticketCategoryText(tk.category) }}</span>
                    </td>
                    <td>
                      <span class="badge" :class="ticketPriorityBadge(tk.priority)">{{ ticketPriorityText(tk.priority) }}</span>
                    </td>
                    <td>
                      <span class="badge" :class="ticketStatusBadge(tk.status)">{{ ticketStatusText(tk.status) }}</span>
                    </td>
                    <td class="mono" style="font-size: 12px; color: var(--text-muted);">
                      {{ formatDateTimeDisplay(tk.last_message_at || tk.created_at) }}
                    </td>
                    <td style="text-align: right; white-space: nowrap;">
                      <button @click="openTicketDetail(tk)" class="btn btn-soft btn-sm" style="margin-right: 4px;">
                        查看对话
                      </button>
                      <button
                        v-if="tk.status !== 'closed'"
                        @click="handleCloseActiveTicket(tk)"
                        class="btn btn-outline btn-sm"
                      >
                        结单
                      </button>
                    </td>
                  </tr>
                  <tr v-if="filteredTickets.length === 0">
                    <td :colspan="isAdmin ? 8 : 7" style="padding: 0;">
                      <div class="empty-state">
                        <div class="empty-state-title">暂无符合条件的客服工单</div>
                        <div class="empty-state-desc">点击右上角「+ 提交新工单」可选择问题分类并关联名下转发规则发起咨询</div>
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
              <div v-if="filteredTickets.length > 0" class="pagination-bar">
                <span>第 {{ ticketsPage }} / {{ ticketsTotalPages }} 页 · 共 {{ filteredTickets.length }} 张工单</span>
                <div class="pagination-controls">
                  <select v-model.number="ticketsPageSize" class="select pagination-select">
                    <option :value="20">20 条/页</option>
                    <option :value="50">50 条/页</option>
                  </select>
                  <button class="btn btn-outline btn-sm" :disabled="ticketsPage <= 1" @click="ticketsPage--">上一页</button>
                  <button class="btn btn-outline btn-sm" :disabled="ticketsPage >= ticketsTotalPages" @click="ticketsPage++">下一页</button>
                </div>
              </div>
            </div>
          </div>

          <!-- 系统设置 (仅管理员) -->
          <div v-if="activeTab === 'settings' && isAdmin" style="max-width: 720px; display: flex; flex-direction: column; gap: 16px;">
            <div class="card" style="display: flex; flex-direction: column; gap: 14px;">
              <div style="font-weight: 600; font-size: 14px;">基础站点与默认权限</div>
              <div class="grid-2">
                <div>
                  <label class="form-label">面板名称</label>
                  <input v-model="settingsForm.site_name" class="input" placeholder="Zachary Panel" />
                </div>
                <div>
                  <label class="form-label">Logo 标识</label>
                  <input v-model="settingsForm.site_logo" class="input" maxlength="4" placeholder="NX" />
                </div>
              </div>

              <div>
                <label class="form-label">系统公告</label>
                <textarea
                  v-model="settingsForm.announcement"
                  rows="2"
                  class="textarea"
                  placeholder="留空则不显示顶部公告"
                ></textarea>
              </div>

              <div class="grid-3">
                <div>
                  <label class="form-label">新用户默认流量 (GB)</label>
                  <input v-model.number="settingsForm.default_quota_gb" type="number" class="input" />
                </div>
                <div>
                  <label class="form-label">新用户默认规则数</label>
                  <input v-model.number="settingsForm.default_max_rules" type="number" class="input" />
                </div>
                <div>
                  <label class="form-label">新用户默认限速 (Mbps)</label>
                  <input v-model.number="settingsForm.default_speed_mbps" type="number" class="input" />
                </div>
              </div>

              <div>
                <label class="form-label">新用户默认分配角色</label>
                <select v-model.number="settingsForm.default_role_group_id" class="select">
                  <option v-for="rg in rolesList" :key="rg.id" :value="rg.id">
                    {{ rg.name }} (可用隧道: {{ parseAllowedIds(rg.allowed_tunnels).map((id) => getTunnelById(id)?.name || '#' + id).join(', ') || '无' }})
                  </option>
                </select>
              </div>

              <div>
                <label style="display: flex; align-items: center; gap: 8px; font-size: 13px; cursor: pointer;">
                  <input type="checkbox" v-model="settingsForm.allow_register" />
                  <span>开放新用户注册（支持邀请码绑定推荐关系）</span>
                </label>
              </div>
            </div>

            <div class="card" style="display: flex; flex-direction: column; gap: 14px;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                  <span style="font-weight: 600; font-size: 14px;">分时段闲时流量倍率 (Off-Peak Dynamic Billing)</span>
                  <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">
                    支持跨午夜时段（如 23:00 ~ 07:00）；闲时窗口内上报流量自动乘以闲时倍率，隧道也可单独设置专属闲时倍率覆盖全局
                  </div>
                </div>
                <label style="display: flex; align-items: center; gap: 6px; font-size: 13px; cursor: pointer; white-space: nowrap;">
                  <input type="checkbox" v-model="settingsForm.offpeak_enabled" />
                  <span>启用闲时倍率</span>
                </label>
              </div>

              <div class="grid-4">
                <div>
                  <label class="form-label">闲时开始 (HH:MM)</label>
                  <input v-model="settingsForm.offpeak_start" class="input mono" placeholder="00:00" />
                </div>
                <div>
                  <label class="form-label">闲时结束 (HH:MM)</label>
                  <input v-model="settingsForm.offpeak_end" class="input mono" placeholder="08:00" />
                </div>
                <div>
                  <label class="form-label">全局闲时倍率 (0=免流)</label>
                  <input
                    v-model.number="settingsForm.offpeak_multiplier"
                    type="number"
                    min="0"
                    max="10"
                    step="0.1"
                    class="input"
                    placeholder="0.5"
                  />
                </div>
                <div>
                  <label class="form-label">计费时区 (IANA)</label>
                  <input v-model="settingsForm.offpeak_timezone" class="input mono" placeholder="Asia/Shanghai" />
                </div>
              </div>
            </div>

            <div class="card" style="display: flex; flex-direction: column; gap: 14px;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-weight: 600; font-size: 14px;">推广返利与邀请分销设置 (Affiliate)</span>
                <label style="display: flex; align-items: center; gap: 6px; font-size: 13px; cursor: pointer;">
                  <input type="checkbox" v-model="settingsForm.affiliate_enabled" />
                  <span>启用邀请返佣自动结算</span>
                </label>
              </div>

              <div class="grid-2">
                <div>
                  <label class="form-label">返佣结算比例 (% ，0-50)</label>
                  <input
                    v-model.number="settingsForm.affiliate_commission_rate"
                    type="number"
                    min="0"
                    max="50"
                    step="0.5"
                    class="input"
                    placeholder="10"
                  />
                </div>
                <div>
                  <label class="form-label">单笔最低提现门槛 (元)</label>
                  <input
                    v-model.number="settingsForm.affiliate_min_withdraw_yuan"
                    type="number"
                    min="1"
                    step="1"
                    class="input"
                    placeholder="10"
                  />
                </div>
              </div>
            </div>

            <div class="card" style="display: flex; flex-direction: column; gap: 14px;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-weight: 600; font-size: 14px;">在线充值与支付网关 (易支付 EPay / USDT)</span>
                <label style="display: flex; align-items: center; gap: 6px; font-size: 13px; cursor: pointer;">
                  <input type="checkbox" v-model="settingsForm.payment_enabled" />
                  <span>启用在线充值</span>
                </label>
              </div>

              <div class="grid-3">
                <div>
                  <label class="form-label">彩虹易支付网关地址</label>
                  <input v-model="settingsForm.epay_url" class="input" placeholder="https://pay.example.com" />
                </div>
                <div>
                  <label class="form-label">商户 ID (PID)</label>
                  <input v-model="settingsForm.epay_pid" class="input" placeholder="1001" />
                </div>
                <div>
                  <label class="form-label">商户密钥 (Key)</label>
                  <input v-model="settingsForm.epay_key" type="password" class="input" placeholder="MD5 签名密钥" />
                </div>
              </div>

              <div class="grid-2">
                <div>
                  <label class="form-label">USDT-TRC20 收款地址（选填）</label>
                  <input v-model="settingsForm.usdt_address" class="input" placeholder="T..." />
                </div>
                <div>
                  <label class="form-label">USDT Webhook 回调密钥 (HMAC-SHA256)</label>
                  <input
                    v-model="settingsForm.usdt_webhook_secret"
                    type="password"
                    class="input"
                    placeholder="回调地址: /api/v1/pay/usdt/notify"
                  />
                </div>
              </div>

              <div>
                <label class="form-label">充值引导说明</label>
                <textarea
                  v-model="settingsForm.recharge_notice"
                  rows="2"
                  class="textarea"
                  placeholder="例如：支持支付宝/微信易支付自动回调到账，或转账后联系管理员确认入账"
                ></textarea>
              </div>
            </div>

            <div class="card" style="display: flex; flex-direction: column; gap: 14px;">
              <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                <span style="font-weight: 600; font-size: 14px;">运维与客服通知中心 (Telegram Bot / 通用 Webhook)</span>
                <div style="display: flex; gap: 14px; align-items: center; flex-wrap: wrap;">
                  <label style="display: flex; align-items: center; gap: 6px; font-size: 13px; cursor: pointer;">
                    <input type="checkbox" v-model="settingsForm.notify_on_node_events" />
                    <span>节点上下线告警</span>
                  </label>
                  <label style="display: flex; align-items: center; gap: 6px; font-size: 13px; cursor: pointer;">
                    <input type="checkbox" v-model="settingsForm.notify_on_quota_events" />
                    <span>流量超额 / 套餐到期告警</span>
                  </label>
                  <label style="display: flex; align-items: center; gap: 6px; font-size: 13px; cursor: pointer;">
                    <input type="checkbox" v-model="settingsForm.notify_on_ticket_events" />
                    <span>新工单 / 工单回复推送</span>
                  </label>
                </div>
              </div>

              <div class="grid-2">
                <div>
                  <label class="form-label">Telegram Bot Token</label>
                  <input
                    v-model="settingsForm.notify_telegram_bot_token"
                    type="password"
                    class="input"
                    placeholder="123456789:AAH..."
                  />
                </div>
                <div>
                  <label class="form-label">Telegram Chat ID</label>
                  <input
                    v-model="settingsForm.notify_telegram_chat_id"
                    class="input"
                    placeholder="-1001234567890 或个人 Chat ID"
                  />
                </div>
              </div>

              <div>
                <label class="form-label">通用 Webhook URL（支持飞书 / 钉钉 / 企业微信 / Slack / 自定义 JSON 接收端）</label>
                <input
                  v-model="settingsForm.notify_webhook_url"
                  class="input"
                  placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/..."
                />
              </div>

              <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 4px;">
                <button @click="sendTestNotify" class="btn btn-soft">发送测试通知</button>
                <button @click="saveSystemSettings" class="btn btn-primary">保存全部设置</button>
              </div>
            </div>

            <div class="card" style="display: flex; flex-direction: column; gap: 12px;">
              <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                <div>
                  <span style="font-weight: 600; font-size: 14px;">外部对接管理 API Key 与管理员双因素认证 (2FA)</span>
                  <span style="font-size: 12px; color: var(--text-muted); margin-left: 8px;">
                    支持通过请求头 <code>X-API-Key: zp_live_...</code> 调用全部管理 API，并为账号绑定 TOTP 动态验证器
                  </span>
                </div>
                <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
                  <button @click="openPasswordModal" class="btn btn-outline btn-sm">
                    {{ user?.totp_enabled ? '双因素认证 (2FA)：已启用' : '配置双因素认证 (2FA)' }}
                  </button>
                  <button @click="generateAdminAPIKey" class="btn btn-primary btn-sm">
                    {{ siteConfig.admin_api_key_prefix ? '轮换生成新 API Key' : '生成管理 API Key' }}
                  </button>
                  <button
                    v-if="siteConfig.admin_api_key_prefix"
                    @click="revokeAdminAPIKey"
                    class="btn btn-danger btn-sm"
                  >
                    吊销 API Key
                  </button>
                </div>
              </div>

              <div style="display: flex; gap: 16px; align-items: center; flex-wrap: wrap; font-size: 12.5px;">
                <div>
                  当前 API Key 状态：
                  <span v-if="siteConfig.admin_api_key_prefix" class="badge badge-success mono">
                    生效中 ({{ siteConfig.admin_api_key_prefix }})
                  </span>
                  <span v-else class="badge badge-neutral">未启用</span>
                </div>
                <div v-if="generatedAdminAPIKey" style="display: flex; align-items: center; gap: 8px;">
                  <span>新生成密钥（仅显示一次）：</span>
                  <code class="mono" style="padding: 3px 8px; background: var(--bg-soft); border-radius: 4px;">
                    {{ generatedAdminAPIKey }}
                  </code>
                  <button @click="copyConnectAddr(generatedAdminAPIKey)" class="btn btn-soft btn-sm">复制</button>
                </div>
              </div>
            </div>

            <div class="card" style="display: flex; flex-direction: column; gap: 12px;">
              <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                <div>
                  <span style="font-weight: 600; font-size: 14px;">数据安全热备与操作审计日志</span>
                  <span style="font-size: 12px; color: var(--text-muted); margin-left: 8px;">
                    记录登录、密码修改、节点/用户/卡密/设置变更与数据库快照导出
                  </span>
                </div>
                <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
                  <input
                    v-model="auditSearchQuery"
                    class="input"
                    style="width: 200px; padding: 5px 10px; font-size: 12.5px;"
                    placeholder="搜索邮箱 / 动作 / IP / 详情..."
                  />
                  <button @click="refreshAuditLogs" class="btn btn-outline btn-sm">刷新日志</button>
                  <button @click="downloadSQLiteBackup" class="btn btn-primary btn-sm">
                    一键导出 SQLite 热备快照 (.db)
                  </button>
                </div>
              </div>

              <div class="table-wrap">
                <table class="table">
                  <thead>
                    <tr>
                      <th>时间</th>
                      <th>操作者</th>
                      <th>动作</th>
                      <th>对象</th>
                      <th>详情</th>
                      <th>来源 IP</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="log in pagedAuditLogs" :key="log.id">
                      <td class="mono" style="font-size: 12px; color: var(--text-secondary);">
                        {{ formatDateDisplay(log.created_at) }}
                      </td>
                      <td style="font-size: 12.5px;">{{ log.user_email || `#${log.user_id}` }}</td>
                      <td>
                        <span class="badge badge-info">{{ log.action }}</span>
                      </td>
                      <td class="mono" style="font-size: 12px;">{{ log.target || '-' }}</td>
                      <td style="font-size: 12.5px; color: var(--text-secondary);">{{ log.detail || '-' }}</td>
                      <td class="mono" style="font-size: 12px; color: var(--text-muted);">{{ log.client_ip || log.ip || '-' }}</td>
                    </tr>
                    <tr v-if="filteredAuditLogs.length === 0">
                      <td colspan="6" style="padding: 0;">
                        <div class="empty-state">
                          <div class="empty-state-title">暂无匹配的审计日志记录</div>
                          <div class="empty-state-desc">当前筛选条件下没有安全审计事件</div>
                        </div>
                      </td>
                    </tr>
                  </tbody>
                </table>
                <div v-if="filteredAuditLogs.length > 0" class="pagination-bar">
                  <span>
                    第 {{ auditPage }} / {{ auditTotalPages }} 页 · 共 {{ filteredAuditLogs.length }} 条记录
                  </span>
                  <div class="pagination-controls">
                    <select v-model.number="auditPageSize" class="select pagination-select">
                      <option :value="20">20 条/页</option>
                      <option :value="50">50 条/页</option>
                      <option :value="100">100 条/页</option>
                    </select>
                    <button class="btn btn-outline btn-sm" :disabled="auditPage <= 1" @click="auditPage--">上一页</button>
                    <button class="btn btn-outline btn-sm" :disabled="auditPage >= auditTotalPages" @click="auditPage++">下一页</button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>

    <!-- 新增 / 编辑转发弹窗 (仅展示当前用户有权使用的隧道) -->
    <div v-if="showRuleModal" class="modal-backdrop" @click.self="showRuleModal = false">
      <div class="modal-box" style="max-width: 580px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <span style="font-weight: 600;">{{ editingRuleId ? '编辑转发规则' : '新增转发规则' }}</span>
          <button @click="showRuleModal = false" class="btn btn-outline btn-sm">✕</button>
        </div>

        <div style="display: flex; flex-direction: column; gap: 12px;">
          <div class="grid-2">
            <div>
              <label class="form-label">隧道线路</label>
              <select v-model="ruleForm.tunnel_line_id" class="select">
                <option v-for="l in authorizedLines" :key="l.id" :value="l.id">
                  {{ l.name }} ({{ l.engine }})
                </option>
              </select>
            </div>
            <div>
              <label class="form-label">规则名称</label>
              <input v-model="ruleForm.name" class="input" placeholder="例如：香港业务主站" />
            </div>
          </div>

          <div class="grid-3">
            <div>
              <label class="form-label">协议</label>
              <select v-model="ruleForm.protocol" class="select">
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="both">TCP+UDP</option>
              </select>
            </div>
            <div>
              <label class="form-label">监听端口</label>
              <input v-model.number="ruleForm.listen_port" type="number" class="input" :placeholder="ruleFormPortHint" />
            </div>
            <div>
              <label class="form-label">多目标调度策略</label>
              <select v-model="ruleForm.load_balance" class="select">
                <option value="round_robin">轮询 (Round Robin)</option>
                <option value="weighted">加权轮询 (Weighted)</option>
                <option value="least_rtt">最低延迟 (Least RTT)</option>
                <option value="failover">主备容灾 (Failover)</option>
                <option value="random">随机调度 (Random)</option>
              </select>
            </div>
          </div>

          <div v-if="ruleForm.protocol === 'tcp'">
            <label class="form-label">SNI / HTTP Host 共享端口路由域名（选填，不解密 TLS）</label>
            <input
              v-model="ruleForm.match_domains"
              class="input mono"
              placeholder="例如 app.example.com, *.api.example.com（配置后多条规则可复用同一入口端口）"
            />
          </div>

          <div>
            <label class="form-label">
              目标地址（每行一个 IP:端口，可选附带 <code>#weight=200</code> 或 <code>#backup</code>）
            </label>
            <textarea
              v-model="ruleForm.targetsText"
              rows="3"
              class="textarea mono"
              placeholder="1.1.1.1:443&#10;1.0.0.1:443#weight=50,backup"
            ></textarea>
          </div>

          <div class="grid-2">
            <div>
              <label class="form-label">PROXY Protocol 源 IP 透传</label>
              <select
                v-model.number="ruleForm.proxy_protocol"
                class="select"
                :disabled="ruleForm.protocol === 'udp'"
              >
                <option :value="0">跟随隧道默认配置</option>
                <option :value="1">开启 PROXY Protocol v1 (文本头)</option>
                <option :value="2">开启 PROXY Protocol v2 (二进制头)</option>
                <option :value="-1">强制关闭</option>
              </select>
            </div>
            <div>
              <label class="form-label">指定出站源 IP（多 IP 机器选填）</label>
              <input
                v-model="ruleForm.outbound_ip"
                class="input mono"
                :placeholder="
                  ruleFormAllowedOutboundIPs.length > 0
                    ? '可选授权 IP，留空使用节点默认'
                    : isAdmin
                      ? '留空使用默认出口网卡 IP'
                      : '该线路暂未开放可选出站 IP'
                "
              />
              <div
                v-if="ruleFormAllowedOutboundIPs.length > 0"
                style="display: flex; gap: 4px; flex-wrap: wrap; margin-top: 4px;"
              >
                <button
                  v-for="oip in ruleFormAllowedOutboundIPs"
                  :key="oip"
                  type="button"
                  class="btn btn-soft btn-sm mono"
                  style="padding: 1px 6px; font-size: 11px;"
                  @click="ruleForm.outbound_ip = oip"
                >
                  {{ oip }}
                </button>
              </div>
            </div>
          </div>

          <div class="grid-3">
            <div>
              <label class="form-label">单规则限速 (Mbps，0=继承)</label>
              <input v-model.number="ruleForm.speed_mbps" type="number" min="0" class="input" placeholder="0=继承套餐" />
            </div>
            <div>
              <label class="form-label">单规则总流量上限 (GB，0=不限)</label>
              <input v-model.number="ruleForm.rule_quota_gb" type="number" min="0" step="1" class="input" placeholder="0=不限" />
            </div>
            <div>
              <label class="form-label">每日流量上限 (GB，0=不限)</label>
              <input v-model.number="ruleForm.daily_quota_gb" type="number" min="0" step="1" class="input" placeholder="0=不限，次日自动恢复" />
            </div>
          </div>

          <div>
            <label class="form-label">来源 IP 访问控制 (ACL)</label>
            <select v-model="ruleForm.access_mode" class="select">
              <option value="off">关闭（允许所有来源 IP）</option>
              <option value="allow">白名单（仅允许指定 IP / CIDR）</option>
              <option value="deny">黑名单（拦截指定 IP / CIDR）</option>
            </select>
          </div>

          <div v-if="ruleForm.access_mode !== 'off'">
            <label class="form-label">
              {{ ruleForm.access_mode === 'allow' ? '允许访问的来源 IP / CIDR 列表' : '禁止访问的来源 IP / CIDR 列表' }}
            </label>
            <input
              v-model="ruleForm.access_cidrs"
              class="input"
              placeholder="多个条目用逗号分隔，例如 203.0.113.5, 198.51.100.0/24"
            />
          </div>

          <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px;">
            <button @click="showRuleModal = false" class="btn btn-outline">取消</button>
            <button @click="submitRule" class="btn btn-primary">保存规则</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 新增 / 编辑隧道弹窗 -->
    <div v-if="showLineModal && isAdmin" class="modal-backdrop" @click.self="showLineModal = false">
      <div class="modal-box" style="max-width: 640px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <span style="font-weight: 600;">{{ editingLineId ? '编辑隧道（支持多跳链式与带宽聚合）' : '新增隧道（支持多跳链式与带宽聚合）' }}</span>
          <button @click="showLineModal = false" class="btn btn-outline btn-sm">✕</button>
        </div>

        <div style="display: flex; flex-direction: column; gap: 12px;">
          <div class="grid-2">
            <div class="mode-card" :class="{ selected: lineForm.type === 'direct' }" @click="lineForm.type = 'direct'">
              端口直转
            </div>
            <div class="mode-card" :class="{ selected: lineForm.type === 'encrypt' }" @click="lineForm.type = 'encrypt'">
              加密隧道 / 链式与聚合
            </div>
          </div>

          <div class="grid-2">
            <div>
              <label class="form-label">隧道名称</label>
              <input v-model="lineForm.name" class="input" placeholder="例如：沪深港三跳专线聚合" />
            </div>
            <div>
              <label class="form-label">基础转发引擎</label>
              <select v-model="lineForm.engine" class="select">
                <option value="native">native（支持全量多跳/Mux/聚合/SNI/PROXY特性）</option>
                <option value="realm">realm</option>
                <option value="gost">gost</option>
                <option value="nftables">nftables</option>
              </select>
            </div>
          </div>

          <div v-if="lineForm.type === 'direct'">
            <label class="form-label">入口节点</label>
            <select v-model="lineForm.ingress_node_id" class="select">
              <option v-for="n in nodes" :key="n.id" :value="n.id">{{ n.name }} ({{ n.connect_ip }})</option>
            </select>
          </div>

          <template v-else>
            <div class="grid-3">
              <div>
                <label class="form-label">入口节点 (Ingress)</label>
                <select v-model="lineForm.ingress_node_id" class="select">
                  <option v-for="n in nodes" :key="n.id" :value="n.id">{{ n.name }}</option>
                </select>
              </div>
              <div>
                <label class="form-label">主出口节点 (Primary Egress)</label>
                <select v-model="lineForm.egress_node_id" class="select">
                  <option v-for="n in nodes" :key="n.id" :value="n.id">{{ n.name }}</option>
                </select>
              </div>
              <div>
                <label class="form-label">传输协议</label>
                <select v-model="lineForm.transport" class="select">
                  <option value="tls">TLS</option>
                  <option value="wss">WSS</option>
                  <option value="ws">WS</option>
                  <option value="quic">QUIC</option>
                  <option value="custom">Custom</option>
                </select>
              </div>
            </div>

            <!-- 链式转发：有序中间跳点构建器 -->
            <div
              style="padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-color); background: var(--bg-soft); display: flex; flex-direction: column; gap: 8px;"
            >
              <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: wrap;">
                <span style="font-weight: 600; font-size: 12.5px;">多跳链式转发中间节点（选填，最多 8 跳，自动防环路校验）</span>
                <div style="display: flex; gap: 6px; align-items: center;">
                  <select v-model.number="hopPickerNodeId" class="select" style="width: 150px; height: 30px; font-size: 12px;">
                    <option v-for="n in nodes" :key="n.id" :value="n.id">#{{ n.id }} {{ n.name }}</option>
                  </select>
                  <button type="button" @click="addHopToLineForm" class="btn btn-soft btn-sm">+ 插入跳点</button>
                </div>
              </div>

              <div style="display: flex; align-items: center; gap: 6px; flex-wrap: wrap; font-size: 12px;">
                <span class="badge badge-primary">入口: {{ nodeNameById(lineForm.ingress_node_id) }}</span>
                <template v-for="(hid, hIdx) in lineHopIds" :key="'edit-hop-' + hid">
                  <span style="color: var(--text-muted);">→</span>
                  <span
                    class="badge badge-info"
                    style="display: inline-flex; align-items: center; gap: 4px; padding-right: 4px;"
                  >
                    <span>跳{{ hIdx + 1 }}: {{ nodeNameById(hid) }}</span>
                    <button
                      v-if="hIdx > 0"
                      type="button"
                      style="border: none; background: transparent; cursor: pointer; font-size: 11px; color: inherit;"
                      title="前移"
                      @click="moveHopInLineForm(hIdx, -1)"
                    >
                      ◀
                    </button>
                    <button
                      v-if="hIdx < lineHopIds.length - 1"
                      type="button"
                      style="border: none; background: transparent; cursor: pointer; font-size: 11px; color: inherit;"
                      title="后移"
                      @click="moveHopInLineForm(hIdx, 1)"
                    >
                      ▶
                    </button>
                    <button
                      type="button"
                      style="border: none; background: transparent; cursor: pointer; font-size: 11px; color: inherit;"
                      title="移除该跳"
                      @click="removeHopFromLineForm(hIdx)"
                    >
                      ✕
                    </button>
                  </span>
                </template>
                <span style="color: var(--text-muted);">→</span>
                <span class="badge badge-purple">
                  {{ lineForm.egress_node_ids.trim() ? '多出口聚合池' : '出口: ' + nodeNameById(lineForm.egress_node_id) }}
                </span>
              </div>
            </div>

            <!-- 带宽聚合：多出口节点池与吞吐加速 -->
            <div
              style="padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-color); background: var(--bg-soft); display: flex; flex-direction: column; gap: 8px;"
            >
              <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: wrap;">
                <span style="font-weight: 600; font-size: 12.5px;">多出口带宽聚合池（选填，留空则使用上方单主出口）</span>
                <div style="display: flex; gap: 6px; align-items: center; flex-wrap: wrap;">
                  <select v-model.number="egressPoolPickerNodeId" class="select" style="width: 135px; height: 30px; font-size: 12px;">
                    <option v-for="n in nodes" :key="n.id" :value="n.id">#{{ n.id }} {{ n.name }}</option>
                  </select>
                  <input
                    v-model.number="egressPoolPickerWeight"
                    type="number"
                    min="1"
                    max="10000"
                    class="input"
                    style="width: 74px; height: 30px; font-size: 12px;"
                    title="节点权重"
                    placeholder="权重"
                  />
                  <label style="display: inline-flex; align-items: center; gap: 4px; font-size: 12px; cursor: pointer;">
                    <input type="checkbox" v-model="egressPoolPickerBackup" />
                    <span>备用</span>
                  </label>
                  <button type="button" @click="addMemberToEgressPool" class="btn btn-soft btn-sm">+ 加入出口池</button>
                </div>
              </div>

              <div class="grid-2">
                <div>
                  <label class="form-label">出口池配置串（节点ID:权重[:backup]）</label>
                  <input
                    v-model="lineForm.egress_node_ids"
                    class="input mono"
                    placeholder="例如 2:200,3:100,4:100:backup"
                  />
                </div>
                <div>
                  <label class="form-label">多出口池调度策略</label>
                  <select v-model="lineForm.load_balance" class="select">
                    <option value="round_robin">轮询分流 (Round Robin)</option>
                    <option value="weighted">按带宽权重聚合 (Weighted)</option>
                    <option value="least_rtt">最低 RTT 优先 (Least RTT)</option>
                    <option value="failover">主备自动容灾 (Failover)</option>
                    <option value="random">随机分流 (Random)</option>
                  </select>
                </div>
              </div>

              <div class="grid-2">
                <div>
                  <label class="form-label">隧道吞吐加速 / 单流带宽聚合模式</label>
                  <select v-model="lineForm.accel_mode" class="select">
                    <option value="none">标准独立连接</option>
                    <option value="mux">Mux 长连接多路复用池（零握手延迟 + 流控背压）</option>
                    <option value="bonding">Bonding 单流多通道条带化聚合（突破单 TCP 窗口瓶颈）</option>
                  </select>
                </div>
                <div v-if="lineForm.accel_mode === 'bonding'">
                  <label class="form-label">单流并行聚合通道数 (2 - 8 条)</label>
                  <input v-model.number="lineForm.bond_links" type="number" min="2" max="8" class="input" />
                </div>
              </div>
            </div>
          </template>

          <div class="grid-2">
            <div>
              <label class="form-label">默认 PROXY Protocol 源 IP 透传</label>
              <select v-model.number="lineForm.proxy_protocol" class="select">
                <option :value="0">默认关闭（规则可单独开启）</option>
                <option :value="1">默认开启 PROXY Protocol v1</option>
                <option :value="2">默认开启 PROXY Protocol v2</option>
              </select>
            </div>
            <div>
              <label class="form-label">隧道专属闲时倍率（0 = 继承全局闲时设置）</label>
              <input
                v-model.number="lineForm.offpeak_multiplier"
                type="number"
                min="0"
                step="0.1"
                class="input"
                placeholder="0 为继承全局闲时倍率"
              />
            </div>
          </div>

          <div class="grid-3">
            <div>
              <label class="form-label">计费方式</label>
              <select v-model="lineForm.billing_mode" class="select">
                <option value="one_way">单向计费</option>
                <option value="two_way">双向计费</option>
              </select>
            </div>
            <div>
              <label class="form-label">流量倍率</label>
              <input v-model.number="lineForm.rate_multiplier" type="number" step="0.1" class="input" />
            </div>
            <div>
              <label class="form-label">端口配额</label>
              <input v-model.number="lineForm.max_port_count" type="number" class="input" />
            </div>
          </div>

          <div>
            <label class="form-label">端口范围（选填）</label>
            <input
              v-model.trim="lineForm.port_range"
              class="input"
              :placeholder="'留空使用入口节点端口范围 ' + (nodes.find((n) => n.id === lineForm.ingress_node_id)?.port_range || '')"
            />
            <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
              该隧道的转发规则只在此范围内分配监听端口，格式如 20000-20999，需在入口节点端口范围之内。
            </div>
          </div>

          <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px;">
            <button @click="showLineModal = false" class="btn btn-outline">取消</button>
            <button @click="submitLine" class="btn btn-primary">保存隧道</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 新增 / 编辑节点弹窗 -->
    <div v-if="showNodeModal && isAdmin" class="modal-backdrop" @click.self="showNodeModal = false">
      <div class="modal-box" style="max-width: 540px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <span style="font-weight: 600;">{{ editingNodeId ? '编辑节点' : '新增节点' }}</span>
          <button @click="showNodeModal = false" class="btn btn-outline btn-sm">✕</button>
        </div>
        <div style="display: flex; flex-direction: column; gap: 12px;">
          <div>
            <label class="form-label">名称</label>
            <input v-model="nodeForm.name" class="input" placeholder="节点名称" />
          </div>
          <div class="grid-2">
            <div>
              <label class="form-label">连接地址 (客户端接入域名 / IP)</label>
              <input v-model="nodeForm.connect_ip" class="input" placeholder="IP 或域名" />
            </div>
            <div>
              <label class="form-label">节点服务器 IP (内部对接 IP)</label>
              <input v-model="nodeForm.server_ip" class="input" placeholder="留空默认同连接地址" />
            </div>
          </div>
          <div class="grid-2">
            <div>
              <label class="form-label">默认出站源 IP（多网卡选填）</label>
              <input v-model="nodeForm.outbound_ip" class="input mono" placeholder="留空由内核路由自动选源" />
            </div>
            <div>
              <label class="form-label">授权租户选用的出站 IP 列表（逗号分隔）</label>
              <input v-model="nodeForm.allowed_outbound_ips" class="input mono" placeholder="例如 203.0.113.10,203.0.113.11" />
            </div>
          </div>
          <div class="grid-2">
            <div>
              <label class="form-label">端口范围</label>
              <input v-model="nodeForm.port_range" class="input" placeholder="10000-50000" />
            </div>
            <div>
              <label class="form-label">流量倍率</label>
              <input v-model.number="nodeForm.traffic_rate" type="number" step="0.1" class="input" />
            </div>
          </div>
          <div class="grid-3">
            <div>
              <label class="form-label">流量限额 (GB)</label>
              <input v-model.number="nodeForm.quota_gb" type="number" step="1" class="input" placeholder="0 为不限" />
            </div>
            <div>
              <label class="form-label">已用流量 (GB)</label>
              <input v-model.number="nodeForm.used_gb" type="number" step="0.1" class="input" />
            </div>
            <div>
              <label class="form-label">月重置日 (0=关闭, 1-28)</label>
              <input v-model.number="nodeForm.reset_day" type="number" min="0" max="28" class="input" placeholder="0 为不自动重置" />
            </div>
          </div>
          <label
            v-if="editingNodeId"
            style="display: flex; align-items: center; gap: 8px; font-size: 13px; cursor: pointer;"
          >
            <input type="checkbox" v-model="nodeForm.maintenance" />
            <span>设为维护模式（自动触发关联的多入口 DNS 容灾组平滑切走解析流量）</span>
          </label>
          <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px;">
            <button @click="showNodeModal = false" class="btn btn-outline">取消</button>
            <button @click="submitNode" class="btn btn-primary">保存</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 新增 / 编辑多入口 DNS 自动容灾组弹窗 -->
    <div v-if="showFailoverModal && isAdmin" class="modal-backdrop" @click.self="showFailoverModal = false">
      <div class="modal-box" style="max-width: 580px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <span style="font-weight: 600;">
            {{ editingFailoverId ? '编辑多入口 DNS 自动容灾组' : '新增多入口 DNS 自动容灾组' }}
          </span>
          <button @click="showFailoverModal = false" class="btn btn-outline btn-sm">✕</button>
        </div>

        <div style="display: flex; flex-direction: column; gap: 12px;">
          <div class="grid-2">
            <div>
              <label class="form-label">容灾组名称</label>
              <input v-model="failoverForm.name" class="input" placeholder="例如：华南电信双入口高可用" />
            </div>
            <div>
              <label class="form-label">接入解析完整域名 (FQDN)</label>
              <input v-model="failoverForm.domain" class="input mono" placeholder="entry.example.com" />
            </div>
          </div>

          <div class="grid-3">
            <div>
              <label class="form-label">DNS 服务商</label>
              <select v-model="failoverForm.provider" class="select">
                <option value="cloudflare">Cloudflare API v4</option>
                <option value="dnspod">腾讯云 DNSPod API</option>
                <option value="webhook">自定义 HMAC Webhook</option>
              </select>
            </div>
            <div>
              <label class="form-label">记录类型</label>
              <select v-model="failoverForm.record_type" class="select">
                <option value="A">A (IPv4)</option>
                <option value="AAAA">AAAA (IPv6)</option>
              </select>
            </div>
            <div>
              <label class="form-label">DNS TTL (秒)</label>
              <input v-model.number="failoverForm.ttl" type="number" min="1" max="86400" class="input" />
            </div>
          </div>

          <div class="grid-2">
            <div>
              <label class="form-label">主入口节点 (Primary Ingress)</label>
              <select v-model.number="failoverForm.primary_node_id" class="select">
                <option v-for="n in nodes" :key="n.id" :value="n.id">
                  #{{ n.id }} {{ n.name }} ({{ n.connect_ip || n.server_ip }})
                </option>
              </select>
            </div>
            <div>
              <label class="form-label">添加备用入口节点 (按优先级顺序接管)</label>
              <div style="display: flex; gap: 6px;">
                <select v-model.number="failoverBackupPickerId" class="select" style="flex: 1;">
                  <option v-for="n in nodes" :key="n.id" :value="n.id">#{{ n.id }} {{ n.name }}</option>
                </select>
                <button type="button" @click="addFailoverBackupNode" class="btn btn-soft btn-sm">+ 添加</button>
              </div>
            </div>
          </div>

          <div
            style="padding: 8px 12px; border-radius: var(--radius-md); background: var(--bg-soft); border: 1px solid var(--border-color); display: flex; align-items: center; gap: 6px; flex-wrap: wrap; font-size: 12px;"
          >
            <span style="color: var(--text-muted);">接管顺序：</span>
            <span class="badge badge-primary">主: {{ nodeNameById(failoverForm.primary_node_id) }}</span>
            <template v-for="(bid, bIdx) in failoverBackupIds" :key="'fb-form-' + bid">
              <span style="color: var(--text-muted);">→</span>
              <span class="badge badge-neutral" style="display: inline-flex; align-items: center; gap: 4px;">
                <span>备{{ bIdx + 1 }}: {{ nodeNameById(bid) }}</span>
                <button
                  type="button"
                  style="border: none; background: transparent; cursor: pointer; font-size: 11px; color: inherit;"
                  @click="removeFailoverBackupNode(bIdx)"
                >
                  ✕
                </button>
              </span>
            </template>
          </div>

          <template v-if="failoverForm.provider === 'cloudflare'">
            <div class="grid-2">
              <div>
                <label class="form-label">Cloudflare Zone ID</label>
                <input v-model="failoverForm.zone_id" class="input mono" placeholder="32 位 Zone ID" />
              </div>
              <div>
                <label class="form-label">Record ID（留空自动查询匹配）</label>
                <input v-model="failoverForm.record_id" class="input mono" placeholder="留空自动发现并缓存" />
              </div>
            </div>
            <div>
              <label class="form-label">
                Cloudflare API Token (需 Zone.DNS 编辑权限){{ failoverForm.has_api_token ? ' — 留空保持原密钥不变' : '' }}
              </label>
              <input
                v-model="failoverForm.api_token"
                type="password"
                class="input mono"
                :placeholder="failoverForm.has_api_token ? '已保存密钥，留空不修改' : '输入 Bearer API Token'"
              />
            </div>
            <label style="display: flex; align-items: center; gap: 8px; font-size: 12.5px; cursor: pointer;">
              <input type="checkbox" v-model="failoverForm.proxied" />
              <span>开启 Cloudflare 橙云代理（非标准端口 TCP/UDP 转发建议保持关闭）</span>
            </label>
          </template>

          <template v-else-if="failoverForm.provider === 'dnspod'">
            <div class="grid-3">
              <div>
                <label class="form-label">主域名（如 example.com）</label>
                <input v-model="failoverForm.zone_id" class="input mono" placeholder="留空自动从 FQDN 推导" />
              </div>
              <div>
                <label class="form-label">主机记录（如 entry）</label>
                <input v-model="failoverForm.sub_domain" class="input mono" placeholder="留空自动推导" />
              </div>
              <div>
                <label class="form-label">Record ID（选填）</label>
                <input v-model="failoverForm.record_id" class="input mono" placeholder="留空自动查询" />
              </div>
            </div>
            <div>
              <label class="form-label">
                DNSPod Token（格式: ID,Token）{{ failoverForm.has_api_token ? ' — 留空保持原密钥不变' : '' }}
              </label>
              <input
                v-model="failoverForm.api_token"
                type="password"
                class="input mono"
                :placeholder="failoverForm.has_api_token ? '已保存密钥，留空不修改' : '例如 123456,abcdef0123456789...'"
              />
            </div>
          </template>

          <template v-else>
            <div>
              <label class="form-label">自定义 DNS 切换 Webhook URL (POST JSON)</label>
              <input v-model="failoverForm.webhook_url" class="input mono" placeholder="https://dns-hook.example.com/switch" />
            </div>
            <div>
              <label class="form-label">
                HMAC-SHA256 签名密钥（请求头 X-Zachary-Signature，选填）{{ failoverForm.has_api_token ? ' — 留空保持原密钥不变' : '' }}
              </label>
              <input
                v-model="failoverForm.api_token"
                type="password"
                class="input mono"
                :placeholder="failoverForm.has_api_token ? '已保存签名密钥，留空不修改' : '用于验签防伪造'"
              />
            </div>
          </template>

          <div class="grid-2">
            <div>
              <label class="form-label">节点离线判定阈值 (秒)</label>
              <input v-model.number="failoverForm.offline_threshold_sec" type="number" min="0" max="3600" class="input" />
            </div>
            <div>
              <label class="form-label">切换防抖冷却时间 (秒)</label>
              <input v-model.number="failoverForm.cooldown_sec" type="number" min="0" max="86400" class="input" />
            </div>
          </div>

          <div style="display: flex; gap: 18px; flex-wrap: wrap;">
            <label style="display: flex; align-items: center; gap: 8px; font-size: 13px; cursor: pointer;">
              <input type="checkbox" v-model="failoverForm.auto_failback" />
              <span>主入口恢复在线后自动回切 (Auto-Failback)</span>
            </label>
            <label style="display: flex; align-items: center; gap: 8px; font-size: 13px; cursor: pointer;">
              <input type="checkbox" v-model="failoverForm.enabled" />
              <span>启用自动巡检容灾</span>
            </label>
          </div>

          <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px;">
            <button @click="showFailoverModal = false" class="btn btn-outline">取消</button>
            <button @click="submitFailoverForm" class="btn btn-primary">保存容灾组</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 修改密码与双因素认证 (2FA) 弹窗 -->
    <div v-if="showPasswordModal" class="modal-backdrop" @click.self="showPasswordModal = false">
      <div class="modal-box" style="max-width: 480px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <span style="font-weight: 600;">安全中心：修改密码与双因素认证 (2FA)</span>
          <button @click="showPasswordModal = false" class="btn btn-outline btn-sm">✕</button>
        </div>
        <div style="display: flex; flex-direction: column; gap: 12px;">
          <div>
            <label class="form-label">原密码</label>
            <input v-model="pwdForm.old" type="password" class="input" autocomplete="current-password" />
          </div>
          <div>
            <label class="form-label">新密码（8-72 位）</label>
            <input v-model="pwdForm.next" type="password" class="input" autocomplete="new-password" />
          </div>
          <div>
            <label class="form-label">确认新密码</label>
            <input v-model="pwdForm.confirm" type="password" class="input" autocomplete="new-password" @keyup.enter="submitChangePassword" />
          </div>
          <p v-if="pwdError" style="font-size: 12px; color: var(--danger-text);">{{ pwdError }}</p>
          <p style="font-size: 12px; color: var(--text-secondary);">修改后其他设备上的登录会立即失效。</p>
          <button @click="submitChangePassword" class="btn btn-primary" style="width: 100%;">确认修改密码</button>

          <hr style="border: none; border-top: 1px solid var(--border-color); margin: 6px 0;" />

          <div style="display: flex; flex-direction: column; gap: 10px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="font-weight: 600; font-size: 13.5px;">TOTP 双因素认证 (Google / Microsoft Authenticator)</span>
              <span class="badge" :class="user?.totp_enabled ? 'badge-success' : 'badge-neutral'">
                {{ user?.totp_enabled ? '已开启' : '未开启' }}
              </span>
            </div>

            <div v-if="!user?.totp_enabled">
              <div v-if="!totpSetupData">
                <button @click="handleStartTOTPSetup" class="btn btn-soft" style="width: 100%;">
                  生成 2FA 绑定密钥
                </button>
              </div>
              <div v-else style="display: flex; flex-direction: column; gap: 8px; font-size: 12.5px;">
                <div>
                  1. 在身份验证器中添加账号并填入 Base32 密钥：
                  <div style="display: flex; align-items: center; gap: 6px; margin-top: 4px;">
                    <code class="mono" style="padding: 4px 8px; background: var(--bg-soft); border-radius: 4px; flex: 1; word-break: break-all;">
                      {{ totpSetupData.secret }}
                    </code>
                    <button @click="copyConnectAddr(totpSetupData.secret)" class="btn btn-outline btn-sm">复制密钥</button>
                    <button @click="copyConnectAddr(totpSetupData.otpauth_url)" class="btn btn-outline btn-sm">复制 URI</button>
                  </div>
                </div>
                <div>
                  <label class="form-label">2. 输入验证器显示的 6 位动态验证码完成激活</label>
                  <div style="display: flex; gap: 8px;">
                    <input
                      v-model="totpVerifyInput"
                      maxlength="6"
                      class="input mono"
                      placeholder="6 位数字验证码"
                      @keyup.enter="handleConfirmEnableTOTP"
                    />
                    <button @click="handleConfirmEnableTOTP" class="btn btn-primary">验证并启用</button>
                  </div>
                </div>
              </div>
            </div>

            <div v-else style="display: flex; flex-direction: column; gap: 8px;">
              <label class="form-label">输入当前密码或 6 位动态验证码以关闭 2FA</label>
              <div style="display: flex; gap: 8px;">
                <input
                  v-model="totpDisableInput"
                  type="password"
                  class="input"
                  placeholder="当前密码 或 6 位验证码"
                  @keyup.enter="handleConfirmDisableTOTP"
                />
                <button @click="handleConfirmDisableTOTP" class="btn btn-danger">关闭 2FA</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 节点对接弹窗 -->
    <div v-if="showInstallModal && installInfo && isAdmin" class="modal-backdrop" @click.self="showInstallModal = false">
      <div class="modal-box" style="max-width: 600px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
          <span style="font-weight: 600;">节点对接</span>
          <button @click="showInstallModal = false" class="btn btn-outline btn-sm">✕</button>
        </div>
        <div style="display: flex; flex-direction: column; gap: 12px; font-size: 12.5px;">
          <div
            v-for="(w, wi) in (installInfo.warnings || [])"
            :key="wi"
            style="padding: 8px 10px; border-radius: var(--radius-md); background: var(--danger-bg, rgba(248,113,113,0.12)); color: var(--danger-text);"
          >
            {{ w }}
          </div>
          <div class="grid-2">
            <div
              class="mode-card"
              :class="{ selected: installMode === 'systemd' }"
              @click="installMode = 'systemd'"
            >
              Systemd 服务
            </div>
            <div
              class="mode-card"
              :class="{ selected: installMode === 'docker' }"
              @click="installMode = 'docker'"
            >
              Docker 容器
            </div>
          </div>

          <div>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
              <span style="font-weight: 600;">安装命令</span>
              <button
                @click="copyConnectAddr(installMode === 'systemd' ? installInfo.systemd_install : installInfo.docker_install)"
                class="btn btn-primary btn-sm"
              >
                复制
              </button>
            </div>
            <pre
              style="background: var(--bg-code); color: #34d399; padding: 12px; border-radius: var(--radius-md); overflow-x: auto; white-space: pre-wrap; word-break: break-all;"
            >{{ installMode === 'systemd' ? installInfo.systemd_install : installInfo.docker_install }}</pre>
          </div>

          <div>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
              <span style="font-weight: 600; color: var(--danger-text);">卸载命令</span>
              <button
                @click="copyConnectAddr(installMode === 'systemd' ? installInfo.systemd_uninstall : installInfo.docker_uninstall)"
                class="btn btn-danger btn-sm"
              >
                复制
              </button>
            </div>
            <pre
              style="background: var(--bg-code); color: #f87171; padding: 10px 12px; border-radius: var(--radius-md); overflow-x: auto; white-space: pre-wrap; word-break: break-all;"
            >{{ installMode === 'systemd' ? installInfo.systemd_uninstall : installInfo.docker_uninstall }}</pre>
          </div>
        </div>
      </div>
    </div>

    <!-- 批量导入转发弹窗 (仅显示已授权隧道) -->
    <div v-if="showBatchModal" class="modal-backdrop" @click.self="showBatchModal = false">
      <div class="modal-box">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <span style="font-weight: 600;">批量导入</span>
          <button @click="showBatchModal = false" class="btn btn-outline btn-sm">✕</button>
        </div>
        <div style="display: flex; flex-direction: column; gap: 12px;">
          <div class="grid-2">
            <div>
              <label class="form-label">隧道</label>
              <select v-model="batchForm.tunnel_line_id" class="select">
                <option v-for="l in authorizedLines" :key="l.id" :value="l.id">{{ l.name }} ({{ l.engine }})</option>
              </select>
            </div>
            <div>
              <label class="form-label">协议</label>
              <select v-model="batchForm.protocol" class="select">
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="both">TCP+UDP</option>
              </select>
            </div>
          </div>
          <div>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
              <label class="form-label" style="margin-bottom: 0;">规则列表（最多 50 条）</label>
              <div>
                <input
                  ref="batchFileInput"
                  type="file"
                  accept=".txt,.csv,.json"
                  style="display: none;"
                  @change="handleBatchFileSelect"
                />
                <button type="button" @click="batchFileInput?.click()" class="btn btn-outline btn-sm">
                  从文件导入 (.txt/.csv/.json)
                </button>
              </div>
            </div>
            <textarea
              v-model="batchForm.rawText"
              rows="6"
              class="textarea"
              placeholder="每行一条：名称|监听端口|目标IP:端口(|协议)&#10;例如：业务节点A|0|1.1.1.1:443|tcp&#10;多目标用分号分隔：业务节点B|0|1.1.1.1:443;1.0.0.1:443"
            ></textarea>
            <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
              支持格式：<code>名称|监听端口|目标地址(|协议)</code>（监听端口填 0 自动分配，多目标用 <code>;</code> 分隔），或 JSON 数组。
            </div>
          </div>
          <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px;">
            <button @click="showBatchModal = false" class="btn btn-outline">取消</button>
            <button @click="submitBatchRules" class="btn btn-primary">导入</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 新增 / 编辑角色弹窗 (角色决定可用隧道) -->
    <div v-if="showRoleModal && isAdmin" class="modal-backdrop" @click.self="showRoleModal = false">
      <div class="modal-box">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <span style="font-weight: 600;">{{ editingRoleId ? '编辑角色与可用隧道' : '新增角色' }}</span>
          <button @click="showRoleModal = false" class="btn btn-outline btn-sm">✕</button>
        </div>
        <div style="display: flex; flex-direction: column; gap: 12px;">
          <div>
            <label class="form-label">角色名称</label>
            <input v-model="roleForm.name" class="input" placeholder="例如：标准角色 / VIP 专线角色" />
          </div>
          <div>
            <label class="form-label">角色说明</label>
            <input v-model="roleForm.description" class="input" placeholder="描述该角色适用的套餐与线路等级" />
          </div>
          <div>
            <label class="form-label">该角色允许使用的隧道</label>
            <div
              style="display: flex; flex-direction: column; gap: 8px; padding: 10px 12px; border: 1px solid var(--border-color); border-radius: var(--radius-md); background: var(--bg-soft);"
            >
              <label
                v-for="l in lines"
                :key="l.id"
                style="display: flex; align-items: center; justify-content: space-between; font-size: 13px; cursor: pointer;"
              >
                <span style="display: flex; align-items: center; gap: 8px;">
                  <input type="checkbox" :value="l.id" v-model="roleForm.tunnelIds" />
                  <span style="font-weight: 500;">{{ l.name }}</span>
                </span>
                <span class="badge" :class="l.type === 'encrypt' ? 'badge-purple' : 'badge-primary'">
                  {{ l.type === 'encrypt' ? '隧道转发' : '端口转发' }} · {{ l.engine }}
                </span>
              </label>
            </div>
          </div>
          <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px;">
            <button @click="showRoleModal = false" class="btn btn-outline">取消</button>
            <button @click="submitRoleForm" class="btn btn-primary">保存角色</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 新增 / 编辑套餐弹窗 (套餐绑定角色) -->
    <div v-if="showPlanModal && isAdmin" class="modal-backdrop" @click.self="showPlanModal = false">
      <div class="modal-box">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <span style="font-weight: 600;">{{ editingPlanId ? '编辑套餐 (绑定角色)' : '新增套餐' }}</span>
          <button @click="showPlanModal = false" class="btn btn-outline btn-sm">✕</button>
        </div>
        <div style="display: flex; flex-direction: column; gap: 12px;">
          <div class="grid-2">
            <div>
              <label class="form-label">套餐名称</label>
              <input v-model="planForm.name" class="input" placeholder="例如：IEPL 专线旗舰版" />
            </div>
            <div>
              <label class="form-label">绑定角色 (决定可用隧道)</label>
              <select v-model.number="planForm.role_group_id" class="select">
                <option v-for="rg in rolesList" :key="rg.id" :value="rg.id">{{ rg.name }}</option>
              </select>
            </div>
          </div>

          <div
            style="padding: 8px 12px; border-radius: var(--radius-md); background: var(--bg-soft); font-size: 12px; color: var(--text-secondary);"
          >
            当前绑定角色可用隧道：
            <span
              v-for="tid in parseAllowedIds(getRoleById(planForm.role_group_id)?.allowed_tunnels)"
              :key="tid"
              class="badge badge-primary"
              style="margin-right: 4px;"
            >
              {{ getTunnelById(tid)?.name || '#' + tid }}
            </span>
            <span v-if="parseAllowedIds(getRoleById(planForm.role_group_id)?.allowed_tunnels).length === 0">无</span>
          </div>

          <div class="grid-2">
            <div>
              <label class="form-label">价格 (元)</label>
              <input v-model.number="planForm.price_yuan" type="number" step="0.1" class="input" />
            </div>
            <div>
              <label class="form-label">周期 (天)</label>
              <input v-model.number="planForm.duration_days" type="number" class="input" />
            </div>
          </div>

          <div class="grid-3">
            <div>
              <label class="form-label">流量配额 (GB)</label>
              <input v-model.number="planForm.quota_gb" type="number" class="input" />
            </div>
            <div>
              <label class="form-label">最大规则数</label>
              <input v-model.number="planForm.max_rules" type="number" class="input" />
            </div>
            <div>
              <label class="form-label">带宽限速 (Mbps)</label>
              <input v-model.number="planForm.speed_mbps" type="number" class="input" />
            </div>
          </div>

          <label style="display: flex; align-items: center; gap: 8px; font-size: 13px; cursor: pointer;">
            <input type="checkbox" v-model="planForm.monthly_reset" />
            <span>按月自动重置已用流量（每满 30 天清零，适合季付 / 年付长周期套餐）</span>
          </label>

          <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px;">
            <button @click="showPlanModal = false" class="btn btn-outline">取消</button>
            <button @click="submitPlanForm" class="btn btn-primary">保存套餐</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 新增 / 编辑用户与分配套餐和角色弹窗 -->
    <div v-if="showUserModal && isAdmin" class="modal-backdrop" @click.self="showUserModal = false">
      <div class="modal-box">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <span style="font-weight: 600;">{{ editingUserId ? '分配用户套餐与角色' : '新增用户' }}</span>
          <button @click="showUserModal = false" class="btn btn-outline btn-sm">✕</button>
        </div>
        <div style="display: flex; flex-direction: column; gap: 12px;">
          <div class="grid-2">
            <div>
              <label class="form-label">邮箱账号</label>
              <input v-model="userForm.email" :disabled="!!editingUserId" class="input" placeholder="user@example.com" />
            </div>
            <div>
              <label class="form-label">{{ editingUserId ? '重置密码 (留空不改)' : '登录密码' }}</label>
              <input v-model="userForm.password" type="password" class="input" placeholder="8-72 位字符" />
            </div>
          </div>

          <div v-if="userForm.role !== 'admin'" class="grid-2">
            <div>
              <label class="form-label">分配套餐 (选择后自动同步角色与配额)</label>
              <select v-model.number="userForm.plan_id" @change="onUserPlanChange" class="select">
                <option :value="0">自定义配额</option>
                <option v-for="p in plans" :key="p.id" :value="p.id">
                  {{ p.name }} ({{ roleNameById(p.role_group_id) }})
                </option>
              </select>
            </div>
            <div>
              <label class="form-label">分配角色 (决定可用隧道)</label>
              <select v-model.number="userForm.role_group_id" class="select">
                <option v-for="rg in rolesList" :key="rg.id" :value="rg.id">{{ rg.name }}</option>
              </select>
            </div>
          </div>

          <div
            v-if="userForm.role !== 'admin'"
            style="padding: 10px 12px; border: 1px solid var(--border-color); border-radius: var(--radius-md); background: var(--bg-soft); font-size: 12.5px;"
          >
            <div style="font-weight: 600; margin-bottom: 6px;">
              当前角色「{{ roleNameById(userForm.role_group_id) }}」授权可用的隧道：
            </div>
            <div style="display: flex; flex-wrap: wrap; gap: 6px;">
              <span
                v-for="tid in parseAllowedIds(getRoleById(userForm.role_group_id)?.allowed_tunnels)"
                :key="tid"
                class="badge badge-primary"
              >
                {{ getTunnelById(tid)?.name || '#' + tid }}
              </span>
              <span
                v-if="parseAllowedIds(getRoleById(userForm.role_group_id)?.allowed_tunnels).length === 0"
                style="color: var(--danger-text);"
              >
                该角色暂未关联任何隧道
              </span>
            </div>
          </div>

          <div class="grid-3">
            <div>
              <label class="form-label">流量配额 (GB)</label>
              <input v-model.number="userForm.quota_gb" type="number" class="input" />
            </div>
            <div>
              <label class="form-label">规则数量</label>
              <input v-model.number="userForm.max_rules" type="number" class="input" />
            </div>
            <div>
              <label class="form-label">限速 (Mbps)</label>
              <input v-model.number="userForm.speed_mbps" type="number" class="input" />
            </div>
          </div>

          <div class="grid-3">
            <div v-if="editingUserId">
              <label class="form-label">已用流量 (GB)</label>
              <input v-model.number="userForm.used_gb" type="number" step="0.1" class="input" />
            </div>
            <div v-if="editingUserId">
              <label class="form-label">账户余额 (元)</label>
              <input v-model.number="userForm.balance_yuan" type="number" step="0.01" class="input" />
            </div>
            <div>
              <label class="form-label">到期时间</label>
              <input v-model="userForm.expire_at" type="date" class="input" />
            </div>
          </div>

          <label style="display: flex; align-items: center; gap: 8px; font-size: 13px; cursor: pointer;">
            <input type="checkbox" v-model="userForm.monthly_reset" />
            <span>按月自动重置已用流量（每满 30 天清零并恢复超额暂停规则）</span>
          </label>

          <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px;">
            <button @click="showUserModal = false" class="btn btn-outline">取消</button>
            <button @click="submitUserEdit" class="btn btn-primary">保存</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 管理员重置用户密码弹窗 -->
    <div v-if="showAdminResetPwdModal && isAdmin && adminResetPwdTarget" class="modal-backdrop" @click.self="showAdminResetPwdModal = false">
      <div class="modal-box" style="max-width: 440px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <span style="font-weight: 600;">重置用户密码</span>
          <button @click="showAdminResetPwdModal = false" class="btn btn-outline btn-sm">✕</button>
        </div>
        <div style="display: flex; flex-direction: column; gap: 12px;">
          <div style="font-size: 13px; color: var(--text-secondary);">
            目标账号：<strong style="color: var(--text-main);">{{ adminResetPwdTarget.email }}</strong>
          </div>
          <div>
            <label class="form-label">指定新密码（8-72 位，或直接点击下方随机生成）</label>
            <input
              v-model="adminResetPwdInput"
              type="text"
              class="input"
              placeholder="输入自定义新密码，或留空使用随机生成"
              @keyup.enter="submitAdminResetPwd(false)"
            />
          </div>
          <p v-if="adminResetPwdError" style="font-size: 12px; color: var(--danger-text);">{{ adminResetPwdError }}</p>
          <div
            v-if="adminResetPwdResult"
            style="padding: 10px 12px; border-radius: var(--radius-md); background: var(--bg-soft); border: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; gap: 8px;"
          >
            <div style="font-size: 12.5px;">
              新密码：<code style="font-weight: 700; font-size: 13.5px;">{{ adminResetPwdResult }}</code>
            </div>
            <button @click="copyConnectAddr(adminResetPwdResult)" class="btn btn-primary btn-sm">复制密码</button>
          </div>
          <p style="font-size: 12px; color: var(--text-muted);">
            重置后该用户在所有设备上的已登录会话将立即失效。
          </p>
          <div style="display: flex; justify-content: flex-end; gap: 8px;">
            <button @click="submitAdminResetPwd(true)" class="btn btn-soft">随机生成并重置</button>
            <button @click="submitAdminResetPwd(false)" class="btn btn-primary">使用自定义密码重置</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 管理员批量生成兑换码 / 卡密弹窗 -->
    <div v-if="showRedeemGenModal && isAdmin" class="modal-backdrop" @click.self="showRedeemGenModal = false">
      <div class="modal-box" style="max-width: 520px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <span style="font-weight: 600;">批量生成兑换码 / 卡密</span>
          <button @click="showRedeemGenModal = false" class="btn btn-outline btn-sm">✕</button>
        </div>
        <div style="display: flex; flex-direction: column; gap: 12px;">
          <div>
            <label class="form-label">卡密类型</label>
            <div class="grid-3">
              <div
                class="mode-card"
                :class="{ active: redeemGenForm.cardType === 'plan' }"
                @click="redeemGenForm.cardType = 'plan'"
              >
                <div class="mode-title">套餐激活卡</div>
                <div class="mode-desc">绑定指定套餐与角色</div>
              </div>
              <div
                class="mode-card"
                :class="{ active: redeemGenForm.cardType === 'balance' }"
                @click="redeemGenForm.cardType = 'balance'"
              >
                <div class="mode-title">余额充值卡</div>
                <div class="mode-desc">直接增加账户余额</div>
              </div>
              <div
                class="mode-card"
                :class="{ active: redeemGenForm.cardType === 'quota' }"
                @click="redeemGenForm.cardType = 'quota'"
              >
                <div class="mode-title">流量时长卡</div>
                <div class="mode-desc">叠加流量与有效天数</div>
              </div>
            </div>
          </div>

          <div v-if="redeemGenForm.cardType === 'plan'" class="grid-3">
            <div>
              <label class="form-label">绑定套餐</label>
              <select v-model.number="redeemGenForm.plan_id" @change="onRedeemGenPlanChange" class="select">
                <option v-for="p in plans" :key="p.id" :value="p.id">{{ p.name }}</option>
              </select>
            </div>
            <div>
              <label class="form-label">包含流量 (GB)</label>
              <input v-model.number="redeemGenForm.quota_gb" type="number" class="input" />
            </div>
            <div>
              <label class="form-label">延长周期 (天)</label>
              <input v-model.number="redeemGenForm.duration_days" type="number" class="input" />
            </div>
          </div>

          <div v-if="redeemGenForm.cardType === 'balance'">
            <label class="form-label">面额 / 充值金额 (元)</label>
            <input v-model.number="redeemGenForm.balance_yuan" type="number" step="0.01" class="input" placeholder="50" />
          </div>

          <div v-if="redeemGenForm.cardType === 'quota'" class="grid-2">
            <div>
              <label class="form-label">叠加流量 (GB)</label>
              <input v-model.number="redeemGenForm.quota_gb" type="number" class="input" />
            </div>
            <div>
              <label class="form-label">延长有效期 (天)</label>
              <input v-model.number="redeemGenForm.duration_days" type="number" class="input" />
            </div>
          </div>

          <div class="grid-3">
            <div>
              <label class="form-label">生成数量 (1-100)</label>
              <input v-model.number="redeemGenForm.count" type="number" min="1" max="100" class="input" />
            </div>
            <div>
              <label class="form-label">卡密前缀</label>
              <input v-model="redeemGenForm.prefix" class="input" maxlength="12" placeholder="ZP" />
            </div>
            <div>
              <label class="form-label">批次备注</label>
              <input v-model="redeemGenForm.note" class="input" placeholder="如：发卡网首批" />
            </div>
          </div>

          <div v-if="lastGeneratedCodes.length > 0" style="display: flex; flex-direction: column; gap: 6px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <label class="form-label" style="margin: 0;">本次生成的 {{ lastGeneratedCodes.length }} 张卡密：</label>
              <button @click="copyConnectAddr(lastGeneratedCodes.join('\n'))" class="btn btn-soft btn-sm">一键复制全部</button>
            </div>
            <textarea
              readonly
              rows="4"
              class="textarea"
              style="font-family: monospace; font-size: 12px;"
              :value="lastGeneratedCodes.join('\n')"
            ></textarea>
          </div>

          <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px;">
            <button @click="showRedeemGenModal = false" class="btn btn-outline">关闭</button>
            <button @click="submitGenerateRedeemCodes" class="btn btn-primary">立即生成并复制</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 在线充值弹窗 -->
    <div v-if="showRechargeModal" class="modal-backdrop" @click.self="showRechargeModal = false">
      <div class="modal-box" style="max-width: 460px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <span style="font-weight: 600;">账户余额在线充值</span>
          <button @click="showRechargeModal = false" class="btn btn-outline btn-sm">✕</button>
        </div>

        <div style="display: flex; flex-direction: column; gap: 12px;">
          <div
            v-if="siteConfig.recharge_notice"
            style="padding: 10px 12px; border-radius: var(--radius-md); background: var(--bg-soft); font-size: 12.5px; color: var(--text-secondary);"
          >
            {{ siteConfig.recharge_notice }}
          </div>

          <div>
            <label class="form-label">充值金额 (元)</label>
            <input v-model.number="rechargeForm.amount_yuan" type="number" min="1" step="1" class="input" />
            <div style="display: flex; gap: 6px; margin-top: 6px;">
              <button
                v-for="preset in [20, 50, 100, 200]"
                :key="preset"
                @click="rechargeForm.amount_yuan = preset"
                class="btn btn-soft btn-sm"
              >
                ¥{{ preset }}
              </button>
            </div>
          </div>

          <div class="grid-2">
            <div>
              <label class="form-label">支付网关</label>
              <select v-model="rechargeForm.gateway" class="select">
                <option value="epay">易支付在线收银台</option>
                <option value="usdt">USDT-TRC20 转账</option>
                <option value="manual">人工审核充值</option>
              </select>
            </div>
            <div v-if="rechargeForm.gateway === 'epay'">
              <label class="form-label">支付方式</label>
              <select v-model="rechargeForm.pay_type" class="select">
                <option value="alipay">支付宝 (Alipay)</option>
                <option value="wxpay">微信支付 (WeChat)</option>
                <option value="qqpay">QQ 钱包</option>
              </select>
            </div>
          </div>

          <div
            v-if="rechargeForm.gateway === 'usdt' && siteConfig.usdt_address"
            style="padding: 10px 12px; border-radius: var(--radius-md); background: var(--bg-soft); font-size: 12px;"
          >
            <div>USDT-TRC20 收款地址：</div>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 4px; gap: 8px;">
              <code style="word-break: break-all;">{{ siteConfig.usdt_address }}</code>
              <button @click="copyConnectAddr(siteConfig.usdt_address)" class="btn btn-soft btn-sm">复制</button>
            </div>
          </div>

          <div
            v-if="lastCreatedOrder"
            style="padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-color); font-size: 12.5px;"
          >
            <div>已创建订单：<code>{{ lastCreatedOrder.order_no }}</code></div>
            <div v-if="safeCreatedOrderPayUrl" style="margin-top: 6px;">
              <a :href="safeCreatedOrderPayUrl" target="_blank" rel="noopener noreferrer" class="btn btn-primary btn-sm">
                前往支付收银台
              </a>
            </div>
          </div>

          <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px;">
            <button @click="showRechargeModal = false" class="btn btn-outline">关闭</button>
            <button @click="submitRechargeOrder" class="btn btn-primary">生成充值订单</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 套餐购买 / 周期重置结算台（支持优惠券实时试算抵扣） -->
    <div v-if="showCheckoutModal && checkoutPlan" class="modal-backdrop" @click.self="showCheckoutModal = false">
      <div class="modal-box" style="max-width: 480px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <span style="font-weight: 600;">
            {{ checkoutScene === 'plan_reset' ? '重置订阅周期与流量结算' : '购买套餐结算台' }}
          </span>
          <button @click="showCheckoutModal = false" class="btn btn-outline btn-sm">✕</button>
        </div>

        <div style="display: flex; flex-direction: column; gap: 12px;">
          <div
            style="padding: 12px 14px; border-radius: var(--radius-md); background: var(--bg-subtle); border: 1px solid var(--border-color); display: flex; flex-direction: column; gap: 6px;"
          >
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-weight: 700; font-size: 14.5px;">{{ checkoutPlan.name }}</span>
                <span class="badge badge-purple">{{ roleNameById(checkoutPlan.role_group_id) }}</span>
              </div>
              <span class="mono" style="font-weight: 700; color: var(--text-main);">
                ¥{{ (checkoutPlan.price_cents / 100).toFixed(2) }}
              </span>
            </div>
            <div style="font-size: 12px; color: var(--text-secondary); display: flex; gap: 14px; flex-wrap: wrap;">
              <span>周期 {{ checkoutPlan.duration_days }} 天</span>
              <span>流量 {{ formatBytes(checkoutPlan.quota_bytes) }}</span>
              <span>规则 {{ checkoutPlan.max_rules }} 条</span>
              <span>限速 {{ checkoutPlan.speed_mbps }} Mbps</span>
            </div>
            <div v-if="checkoutScene === 'plan_reset'" style="font-size: 11.5px; color: var(--text-muted);">
              支付后将立即清零已用流量、顺延 {{ checkoutPlan.duration_days }} 天有效期并自动恢复超额暂停规则。
            </div>
          </div>

          <div>
            <label class="form-label">优惠券 / 折扣码（选填，实时试算抵扣）</label>
            <div style="display: flex; gap: 8px;">
              <input
                v-model="checkoutCouponInput"
                type="text"
                maxlength="48"
                class="input mono"
                placeholder="输入优惠券码，例如 ZP88 / NEW20"
                @keyup.enter="handlePreviewCheckoutCoupon"
              />
              <button
                type="button"
                @click="handlePreviewCheckoutCoupon"
                class="btn btn-soft"
                :disabled="checkoutPreviewLoading"
              >
                {{ checkoutPreviewLoading ? '试算中...' : '试算抵扣' }}
              </button>
              <button
                v-if="checkoutCouponPreview || checkoutCouponInput"
                type="button"
                @click="clearCheckoutCoupon"
                class="btn btn-outline btn-sm"
              >
                清除
              </button>
            </div>
            <div v-if="checkoutCouponError" style="font-size: 12px; color: var(--danger-text); margin-top: 5px;">
              {{ checkoutCouponError }}
            </div>
          </div>

          <div v-if="checkoutCouponPreview" class="coupon-preview-box">
            <div>
              <div style="font-weight: 700;">
                已应用「{{ checkoutCouponPreview.name }}」({{ checkoutCouponPreview.coupon_code }})
              </div>
              <div style="font-size: 11.5px; opacity: 0.9; margin-top: 2px;">
                原价 ¥{{ (checkoutCouponPreview.original_cents / 100).toFixed(2) }} · 已减免 -¥{{ (checkoutCouponPreview.discount_cents / 100).toFixed(2) }}
              </div>
            </div>
            <span class="mono" style="font-weight: 700; font-size: 15px;">
              实付 ¥{{ (checkoutCouponPreview.payable_cents / 100).toFixed(2) }}
            </span>
          </div>

          <div
            style="padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; font-size: 13px;"
          >
            <span style="color: var(--text-secondary);">
              当前账户余额：<strong class="mono" style="color: var(--text-main);">¥{{ ((user?.balance_cents || 0) / 100).toFixed(2) }}</strong>
            </span>
            <span>
              应付金额：<strong class="mono" style="font-size: 16px; color: var(--primary-text);">¥{{ (checkoutPayableCents / 100).toFixed(2) }}</strong>
            </span>
          </div>

          <div
            v-if="!isAdmin && (user?.balance_cents || 0) < checkoutPayableCents"
            style="display: flex; justify-content: space-between; align-items: center; gap: 8px; padding: 8px 12px; border-radius: var(--radius-md); background: var(--warning-soft); border: 1px solid var(--warning-border); color: var(--warning-text); font-size: 12px;"
          >
            <span>当前账户余额不足以支付实付金额</span>
            <button
              type="button"
              @click="showCheckoutModal = false; openRechargeModal()"
              class="btn btn-outline btn-sm"
            >
              前往充值
            </button>
          </div>

          <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px;">
            <button @click="showCheckoutModal = false" class="btn btn-outline">取消</button>
            <button
              @click="confirmCheckoutPayment"
              class="btn btn-primary"
              :disabled="checkoutSubmitting || (!isAdmin && (user?.balance_cents || 0) < checkoutPayableCents)"
            >
              {{ checkoutSubmitting ? '处理中...' : `确认扣款支付 ¥${(checkoutPayableCents / 100).toFixed(2)}` }}
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- 管理员新增 / 编辑优惠券弹窗 -->
    <div v-if="showCouponModal && isAdmin" class="modal-backdrop" @click.self="showCouponModal = false">
      <div class="modal-box" style="max-width: 540px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <span style="font-weight: 600;">{{ editingCouponId ? '编辑优惠券 / 折扣码' : '新增优惠券 / 折扣码' }}</span>
          <button @click="showCouponModal = false" class="btn btn-outline btn-sm">✕</button>
        </div>

        <div style="display: flex; flex-direction: column; gap: 12px;">
          <div class="grid-2">
            <div
              class="mode-card"
              :class="{ active: couponForm.type === 'percent' }"
              @click="couponForm.type = 'percent'"
            >
              <div class="mode-title">百分比折扣券</div>
              <div class="mode-desc">按比例减免，可设最高封顶</div>
            </div>
            <div
              class="mode-card"
              :class="{ active: couponForm.type === 'fixed' }"
              @click="couponForm.type = 'fixed'"
            >
              <div class="mode-title">固定金额满减券</div>
              <div class="mode-desc">满足门槛直接立减固定金额</div>
            </div>
          </div>

          <div class="grid-2">
            <div>
              <label class="form-label">优惠券码（留空自动生成）</label>
              <input
                v-model="couponForm.code"
                :disabled="!!editingCouponId"
                class="input mono"
                maxlength="48"
                placeholder="例如：VIP80 / SAVE10"
              />
            </div>
            <div>
              <label class="form-label">优惠券名称</label>
              <input v-model="couponForm.name" class="input" placeholder="例如：春季专线 8 折券" />
            </div>
          </div>

          <div class="grid-3">
            <div v-if="couponForm.type === 'percent'">
              <label class="form-label">减免比例 (% , 如 20=8折)</label>
              <input v-model.number="couponForm.percent_value" type="number" min="1" max="100" class="input" />
            </div>
            <div v-else>
              <label class="form-label">立减金额 (元)</label>
              <input v-model.number="couponForm.fixed_yuan" type="number" min="0.01" step="0.5" class="input" />
            </div>
            <div>
              <label class="form-label">最低消费门槛 (元, 0=无门槛)</label>
              <input v-model.number="couponForm.min_spend_yuan" type="number" min="0" step="1" class="input" />
            </div>
            <div v-if="couponForm.type === 'percent'">
              <label class="form-label">最高减免封顶 (元, 0=不封顶)</label>
              <input v-model.number="couponForm.max_discount_yuan" type="number" min="0" step="1" class="input" />
            </div>
          </div>

          <div class="grid-2">
            <div>
              <label class="form-label">生效日期（选填）</label>
              <input v-model="couponForm.starts_at" type="date" class="input" />
            </div>
            <div>
              <label class="form-label">失效日期（选填）</label>
              <input v-model="couponForm.ends_at" type="date" class="input" />
            </div>
          </div>

          <div class="grid-2">
            <div>
              <label class="form-label">总可用次数（0 = 不限总次数）</label>
              <input v-model.number="couponForm.max_uses" type="number" min="0" class="input" />
            </div>
            <div>
              <label class="form-label">单用户限用次数（0 = 不限）</label>
              <input v-model.number="couponForm.per_user_limit" type="number" min="0" class="input" />
            </div>
          </div>

          <div>
            <label class="form-label">限定适用套餐（不勾选代表全场付费套餐通用）</label>
            <div
              style="display: flex; flex-wrap: wrap; gap: 10px; padding: 10px 12px; border: 1px solid var(--border-color); border-radius: var(--radius-md); background: var(--bg-subtle);"
            >
              <label
                v-for="p in plans"
                :key="p.id"
                style="display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px; cursor: pointer;"
              >
                <input type="checkbox" :value="p.id" v-model="couponForm.allowedPlanIds" />
                <span>{{ p.name }} (¥{{ (p.price_cents / 100).toFixed(2) }})</span>
              </label>
            </div>
          </div>

          <label style="display: flex; align-items: center; gap: 8px; font-size: 13px; cursor: pointer;">
            <input type="checkbox" v-model="couponForm.active" />
            <span>立即启用该优惠券</span>
          </label>

          <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px;">
            <button @click="showCouponModal = false" class="btn btn-outline">取消</button>
            <button @click="submitCouponForm" class="btn btn-primary">保存优惠券</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 申请推广佣金提现弹窗 -->
    <div v-if="showWithdrawModal" class="modal-backdrop" @click.self="showWithdrawModal = false">
      <div class="modal-box" style="max-width: 440px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <span style="font-weight: 600;">申请推广佣金提现</span>
          <button @click="showWithdrawModal = false" class="btn btn-outline btn-sm">✕</button>
        </div>

        <div style="display: flex; flex-direction: column; gap: 12px;">
          <div
            style="padding: 10px 12px; border-radius: var(--radius-md); background: var(--bg-subtle); border: 1px solid var(--border-color); font-size: 12.5px; display: flex; justify-content: space-between;"
          >
            <span>可提现佣金：<strong class="mono">¥{{ ((affiliateOverview?.commission_balance_cents || 0) / 100).toFixed(2) }}</strong></span>
            <span style="color: var(--text-muted);">最低 ¥{{ ((affiliateOverview?.min_withdraw_cents || 1000) / 100).toFixed(2) }}</span>
          </div>

          <div class="grid-2">
            <div>
              <label class="form-label">提现金额 (元)</label>
              <input v-model.number="withdrawForm.amount_yuan" type="number" min="1" step="0.01" class="input" />
            </div>
            <div>
              <label class="form-label">收款方式</label>
              <select v-model="withdrawForm.method" class="select">
                <option value="usdt">USDT-TRC20 钱包</option>
                <option value="alipay">支付宝 (Alipay)</option>
                <option value="wechat">微信收款</option>
                <option value="bank">银行卡转账</option>
              </select>
            </div>
          </div>

          <div>
            <label class="form-label">收款地址 / 收款账号</label>
            <input
              v-model="withdrawForm.account"
              class="input mono"
              placeholder="请输入准确的 TRC20 地址或收款账号"
            />
          </div>

          <div>
            <label class="form-label">收款人姓名备注（选填，支付宝 / 银行卡建议填写）</label>
            <input v-model="withdrawForm.real_name" class="input" placeholder="用于财务核对收款人" />
          </div>

          <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px;">
            <button @click="showWithdrawModal = false" class="btn btn-outline">取消</button>
            <button @click="submitWithdrawRequest" class="btn btn-primary">提交提现申请</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 提交新客服工单弹窗 -->
    <div v-if="showCreateTicketModal" class="modal-backdrop" @click.self="showCreateTicketModal = false">
      <div class="modal-box" style="max-width: 520px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <span style="font-weight: 600;">提交技术支持与客服工单</span>
          <button @click="showCreateTicketModal = false" class="btn btn-outline btn-sm">✕</button>
        </div>

        <div style="display: flex; flex-direction: column; gap: 12px;">
          <div>
            <label class="form-label">工单标题</label>
            <input
              v-model="ticketCreateForm.subject"
              class="input"
              maxlength="160"
              placeholder="简要描述您遇到的问题，例如：深港专线端口连通性排查"
            />
          </div>

          <div class="grid-2">
            <div>
              <label class="form-label">问题分类</label>
              <select v-model="ticketCreateForm.category" class="select">
                <option value="network">线路与网络</option>
                <option value="rule">转发规则排障</option>
                <option value="billing">账单与支付</option>
                <option value="account">账号与权限</option>
                <option value="general">综合咨询</option>
              </select>
            </div>
            <div>
              <label class="form-label">紧急程度</label>
              <select v-model="ticketCreateForm.priority" class="select">
                <option value="low">低优（一般建议）</option>
                <option value="normal">常规</option>
                <option value="high">高优（影响业务）</option>
                <option value="urgent">紧急（线路中断）</option>
              </select>
            </div>
          </div>

          <div>
            <label class="form-label">关联名下转发规则（选填，便于技术快速定位端口与节点）</label>
            <select v-model.number="ticketCreateForm.rule_id" class="select">
              <option :value="0">不关联特定转发规则</option>
              <option v-for="r in visibleRules" :key="r.id" :value="r.id">
                #{{ r.id }} {{ r.name }} ({{ nodeConnectIPById(r.ingress_node_id) }}:{{ r.listen_port }} · {{ r.protocol.toUpperCase() }})
              </option>
            </select>
          </div>

          <div>
            <label class="form-label">详细问题描述</label>
            <textarea
              v-model="ticketCreateForm.message"
              rows="4"
              class="textarea"
              placeholder="请详细说明故障现象、测试时间、源端地区或相关订单号..."
            ></textarea>
          </div>

          <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px;">
            <button @click="showCreateTicketModal = false" class="btn btn-outline">取消</button>
            <button @click="submitCreateTicket" class="btn btn-primary">提交工单</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 工单对话详情与流转处理弹窗 -->
    <div v-if="showTicketDetailModal && activeTicket" class="modal-backdrop" @click.self="showTicketDetailModal = false">
      <div class="modal-box" style="max-width: 640px;">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 10px; margin-bottom: 12px;">
          <div>
            <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
              <span class="mono" style="font-size: 12px; color: var(--text-muted);">{{ activeTicket.ticket_no }}</span>
              <span class="badge badge-neutral">{{ ticketCategoryText(activeTicket.category) }}</span>
              <span class="badge" :class="ticketPriorityBadge(activeTicket.priority)">
                {{ ticketPriorityText(activeTicket.priority) }}
              </span>
              <span class="badge" :class="ticketStatusBadge(activeTicket.status)">
                {{ ticketStatusText(activeTicket.status) }}
              </span>
            </div>
            <div style="font-weight: 700; font-size: 15px; margin-top: 6px;">{{ activeTicket.subject }}</div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 3px; display: flex; gap: 12px; flex-wrap: wrap;">
              <span v-if="isAdmin">提交人：{{ activeTicket.user_email }}</span>
              <span v-if="activeTicket.rule_name" class="mono">关联规则：{{ activeTicket.rule_name }}</span>
            </div>
          </div>
          <button @click="showTicketDetailModal = false" class="btn btn-outline btn-sm">✕</button>
        </div>

        <!-- 管理员快捷流转栏 -->
        <div
          v-if="isAdmin"
          style="display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: wrap; padding: 8px 12px; margin-bottom: 10px; border-radius: var(--radius-md); background: var(--bg-subtle); border: 1px solid var(--border-color); font-size: 12px;"
        >
          <span style="font-weight: 600; color: var(--text-secondary);">客服工单流转操作：</span>
          <div style="display: flex; align-items: center; gap: 6px; flex-wrap: wrap;">
            <button
              type="button"
              @click="handleAdminTicketStatusChange('open')"
              class="btn btn-outline btn-sm"
              :disabled="activeTicket.status === 'open'"
            >
              设为待受理
            </button>
            <button
              type="button"
              @click="handleAdminTicketStatusChange('answered')"
              class="btn btn-soft btn-sm"
              :disabled="activeTicket.status === 'answered'"
            >
              标记已回复
            </button>
            <button
              type="button"
              @click="handleAdminTicketStatusChange('closed')"
              class="btn btn-danger btn-sm"
              :disabled="activeTicket.status === 'closed'"
            >
              直接结单
            </button>
          </div>
        </div>

        <div ref="ticketThreadRef" class="chat-thread">
          <div
            v-for="msg in activeTicketMessages"
            :key="msg.id"
            class="chat-msg"
            :class="(isAdmin && msg.sender_role === 'admin') || (!isAdmin && msg.sender_id === user?.id) ? 'self' : 'peer'"
          >
            <div class="chat-meta">
              <span class="badge" :class="msg.sender_role === 'admin' ? 'badge-purple' : 'badge-info'">
                {{ msg.sender_role === 'admin' ? '技术客服' : '用户' }}
              </span>
              <span>{{ msg.sender_email }}</span>
              <span class="mono">{{ formatDateTimeDisplay(msg.created_at) }}</span>
            </div>
            <div class="chat-bubble">{{ msg.content }}</div>
          </div>
        </div>

        <div v-if="activeTicket.status !== 'closed' || isAdmin" style="margin-top: 12px; display: flex; flex-direction: column; gap: 8px;">
          <textarea
            v-model="ticketReplyInput"
            rows="3"
            class="textarea"
            :placeholder="isAdmin ? '输入客服处理回复（发送后将自动标记为已回复并触发通知）...' : '继续补充说明或追问客服...'"
          ></textarea>
          <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px;">
            <button
              v-if="activeTicket.status !== 'closed'"
              type="button"
              @click="handleCloseActiveTicket()"
              class="btn btn-outline btn-sm"
            >
              已解决，关闭工单
            </button>
            <span v-else style="font-size: 12px; color: var(--text-muted);">管理员回复将自动重新激活该已关闭工单</span>
            <button type="button" @click="submitTicketReply" class="btn btn-primary">发送回复</button>
          </div>
        </div>
        <div
          v-else
          style="margin-top: 12px; padding: 10px 12px; border-radius: var(--radius-md); background: var(--bg-subtle); text-align: center; font-size: 12.5px; color: var(--text-muted);"
        >
          该工单已结单关闭，如有新的技术或账单问题请点击「+ 提交新工单」。
        </div>
      </div>
    </div>

    <!-- 全局快速检索与跳转面板 (Ctrl / Cmd + K) -->
    <div v-if="showCommandPalette && token" class="cmdk-backdrop" @click.self="showCommandPalette = false">
      <div class="cmdk-modal" role="dialog" aria-modal="true" aria-label="快速检索与跳转面板">
        <div class="cmdk-input-wrap">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8"></circle>
            <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
          </svg>
          <input
            ref="cmdkInputRef"
            v-model="cmdkQuery"
            type="text"
            class="cmdk-input"
            placeholder="输入关键字搜索页面、操作、转发规则、端口、节点或用户..."
            @keydown.down.prevent="moveCmdkSelection(1)"
            @keydown.up.prevent="moveCmdkSelection(-1)"
            @keydown.enter.prevent="executeCmdkSelection"
          />
          <button type="button" class="btn btn-outline btn-sm" @click="showCommandPalette = false">Esc</button>
        </div>

        <div class="cmdk-list">
          <button
            v-for="(item, idx) in filteredCommandItems"
            :key="item.id"
            type="button"
            class="cmdk-item"
            :class="{ active: idx === cmdkActiveIndex }"
            @mouseenter="cmdkActiveIndex = idx"
            @click="runCommandItem(item)"
          >
            <div class="cmdk-item-main">
              <span class="badge" :class="item.badgeClass || 'badge-neutral'">{{ item.category }}</span>
              <span class="cmdk-item-title">{{ item.title }}</span>
              <span v-if="item.subtitle" class="cmdk-item-sub">{{ item.subtitle }}</span>
            </div>
            <span class="kbd-shortcut">↵</span>
          </button>

          <div v-if="filteredCommandItems.length === 0" class="empty-state" style="padding: 26px 16px;">
            <div class="empty-state-title">未找到匹配的页面、规则或快捷操作</div>
            <div class="empty-state-desc">请尝试搜索端口、目标 IP、隧道名称或导航模块</div>
          </div>
        </div>

        <div class="cmdk-footer">
          <span>支持搜索：导航视图 · 快捷动作 · 转发规则 · 套餐 · 节点 · 用户</span>
          <span>↑↓ 选择 · Enter 执行 · Esc 关闭</span>
        </div>
      </div>
    </div>
  </div>
</template>
