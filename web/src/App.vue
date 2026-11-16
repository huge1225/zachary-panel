<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import {
  api,
  formatBytes,
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
  type TargetEndpoint,
  type SystemConfig,
} from './api/client'

const isDark = ref(false)
function toggleTheme() {
  isDark.value = !isDark.value
  document.documentElement.classList.toggle('dark', isDark.value)
}

const autoRefresh = ref(true)

const token = ref<string | null>(localStorage.getItem('nexus_token'))
const emailInput = ref('')
const passwordInput = ref('')
const authError = ref('')

const activeTab = ref<'dashboard' | 'rules' | 'lines' | 'nodes' | 'roles' | 'users' | 'store' | 'settings'>('dashboard')
const tabTitleMap: Record<string, string> = {
  dashboard: '概览',
  rules: '转发管理',
  lines: '隧道管理',
  nodes: '节点管理',
  roles: '角色管理',
  users: '用户管理',
  store: '套餐管理',
  settings: '系统设置',
}
const currentTabTitle = computed(() => tabTitleMap[activeTab.value] || '')

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

const isAdmin = computed(() => user.value?.role === 'admin')

function parseAllowedIds(str?: string): number[] {
  if (!str) return []
  return str
    .split(',')
    .map((s) => Number(s.trim()))
    .filter((n) => n > 0)
}

function getRoleById(id?: number): RoleGroup | undefined {
  if (!id) return undefined
  return rolesList.value.find((r) => r.id === id)
}

function roleNameById(id?: number): string {
  return getRoleById(id)?.name || '未分配角色'
}

function planNameById(id?: number): string {
  if (!id) return '自定义配额'
  return plans.value.find((p) => p.id === id)?.name || '自定义配额'
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
const ruleFilterTunnelId = ref<number>(0)
const ruleFilterProtocol = ref<string>('all')
const ruleFilterStatus = ref<string>('all')

const filteredRules = computed(() => {
  const q = ruleSearchQuery.value.trim().toLowerCase()
  return visibleRules.value.filter((r) => {
    if (ruleFilterTunnelId.value > 0 && r.tunnel_line_id !== ruleFilterTunnelId.value) return false
    if (ruleFilterProtocol.value !== 'all' && r.protocol !== ruleFilterProtocol.value) return false
    if (ruleFilterStatus.value === 'running' && !r.enabled) return false
    if (ruleFilterStatus.value === 'paused' && r.enabled) return false
    if (q) {
      const matchName = (r.name || '').toLowerCase().includes(q)
      const matchPort = String(r.listen_port).includes(q)
      const matchTarget = (r.targets_json || '').toLowerCase().includes(q)
      const matchUser = isAdmin.value && userEmailById(r.user_id).toLowerCase().includes(q)
      if (!matchName && !matchPort && !matchTarget && !matchUser) return false
    }
    return true
  })
})

const userSearchQuery = ref('')
const userFilterPlanId = ref<number>(-1)
const userFilterRoleId = ref<number>(-1)
const userFilterStatus = ref<string>('all')

const filteredUsersList = computed(() => {
  const q = userSearchQuery.value.trim().toLowerCase()
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

// --- 转发新增与编辑 ---
const showRuleModal = ref(false)
const editingRuleId = ref<number | null>(null)
const ruleForm = ref({
  name: '',
  tunnel_line_id: 1,
  protocol: 'tcp' as 'tcp' | 'udp' | 'both',
  listen_port: 0,
  load_balance: 'round_robin' as 'round_robin' | 'failover',
  targetsText: '1.1.1.1:443',
  speed_mbps: 0,
  access_mode: 'off' as 'off' | 'allow' | 'deny',
  access_cidrs: '',
})

// 当前选中隧道（或其入口节点）的可用端口范围，用于监听端口输入提示
const ruleFormPortHint = computed(() => {
  const line = lines.value.find((l) => l.id === ruleForm.value.tunnel_line_id)
  if (!line) return '留空自动分配'
  const range = line.port_range || nodes.value.find((n) => n.id === line.ingress_node_id)?.port_range || ''
  return range ? `留空自动分配（${range}）` : '留空自动分配'
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
    load_balance: rule.load_balance,
    targetsText: targets.map((t) => t.address).join('\n'),
    speed_mbps: rule.speed_mbps,
    access_mode: (rule.access_mode as 'off' | 'allow' | 'deny') || 'off',
    access_cidrs: rule.access_cidrs || '',
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
  }
  showRuleModal.value = true
}

// --- 隧道新增与编辑 ---
const showLineModal = ref(false)
const editingLineId = ref<number | null>(null)
const lineForm = ref({
  name: '',
  type: 'direct' as 'direct' | 'encrypt',
  ingress_node_id: 1,
  egress_node_id: 2,
  transport: 'tls' as 'raw' | 'tls' | 'ws' | 'wss' | 'quic' | 'custom',
  engine: 'realm' as EngineType,
  billing_mode: 'one_way' as 'one_way' | 'two_way',
  rate_multiplier: 1.0,
  max_port_count: 50,
  port_range: '',
})

function openCreateLineModal() {
  if (!isAdmin.value) return
  editingLineId.value = null
  lineForm.value = {
    name: '',
    type: 'direct',
    ingress_node_id: nodes.value[0]?.id || 1,
    egress_node_id: nodes.value[nodes.value.length - 1]?.id || 1,
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
  lineForm.value = {
    name: line.name,
    type: line.type,
    ingress_node_id: line.ingress_node_id,
    egress_node_id: line.egress_node_id || nodes.value[0]?.id || 1,
    transport: line.transport || 'tls',
    engine: line.engine,
    billing_mode: line.billing_mode || 'one_way',
    rate_multiplier: line.rate_multiplier,
    max_port_count: line.max_port_count || 50,
    port_range: line.port_range || '',
  }
  showLineModal.value = true
}

// --- 节点新增与编辑 ---
const GB = 1024 * 1024 * 1024
const showNodeModal = ref(false)
const editingNodeId = ref<number | null>(null)
const nodeForm = ref({
  name: '',
  connect_ip: '',
  server_ip: '',
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
    port_range: node.port_range,
    traffic_rate: node.traffic_rate,
    quota_gb: Math.round((node.quota_bytes || 0) / GB),
    used_gb: Number(((node.used_bytes || 0) / GB).toFixed(1)),
    reset_day: node.reset_day || 0,
  }
  showNodeModal.value = true
}

const probeResults = ref<Record<number, { tunnel_ms?: number; latencies: Record<string, number> }>>({})
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
    filteredRules.value.length > 0 &&
    filteredRules.value.every((r) => selectedRuleIds.value.includes(r.id)),
)

function toggleSelectAllRules(e: Event) {
  const checked = (e.target as HTMLInputElement).checked
  if (checked) {
    selectedRuleIds.value = filteredRules.value.map((r) => r.id)
  } else {
    selectedRuleIds.value = []
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
  targets: TargetEndpoint[]
  protocol?: 'tcp' | 'udp' | 'both'
  load_balance?: 'round_robin' | 'failover'
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
            const lb = ['round_robin', 'failover'].includes(String(item.load_balance || ''))
              ? (String(item.load_balance) as 'round_robin' | 'failover')
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
          load_balance?: 'round_robin' | 'failover'
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
  const reader = new FileReader()
  reader.onload = () => {
    batchForm.value.rawText = String(reader.result || '')
    showToast(`已读取文件 ${file.name}`)
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

function exportRulesToClipboard() {
  const source =
    validSelectedRuleIds.value.length > 0
      ? filteredRules.value.filter((r) => validSelectedRuleIds.value.includes(r.id))
      : filteredRules.value
  const text = source
    .map((r) => {
      const addrs = parseTargets(r.targets_json)
        .map((t) => t.address)
        .filter(Boolean)
        .join(';')
      return `${r.name}|${r.listen_port}|${addrs}|${r.protocol}`
    })
    .join('\n')
  copyConnectAddr(text)
  showToast(`已导出 ${source.length} 条规则到剪贴板`)
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
  recharge_notice: '',
  notify_telegram_bot_token: '',
  notify_telegram_chat_id: '',
  notify_webhook_url: '',
  notify_on_node_events: false,
  notify_on_quota_events: false,
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
    recharge_notice: siteConfig.value.recharge_notice || '',
    notify_telegram_bot_token: siteConfig.value.notify_telegram_bot_token || '',
    notify_telegram_chat_id: siteConfig.value.notify_telegram_chat_id || '',
    notify_webhook_url: siteConfig.value.notify_webhook_url || '',
    notify_on_node_events: !!siteConfig.value.notify_on_node_events,
    notify_on_quota_events: !!siteConfig.value.notify_on_quota_events,
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
      recharge_notice: settingsForm.value.recharge_notice.trim(),
      notify_telegram_bot_token: settingsForm.value.notify_telegram_bot_token.trim(),
      notify_telegram_chat_id: settingsForm.value.notify_telegram_chat_id.trim(),
      notify_webhook_url: settingsForm.value.notify_webhook_url.trim(),
      notify_on_node_events: settingsForm.value.notify_on_node_events,
      notify_on_quota_events: settingsForm.value.notify_on_quota_events,
    })
    siteConfig.value = updated
    document.title = siteConfig.value.site_name
    showToast('面板基础、支付与告警配置已保存')
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

const filteredAuditLogs = computed(() => {
  const q = auditSearchQuery.value.trim().toLowerCase()
  return auditLogsList.value.filter((item) => {
    if (auditFilterAction.value !== 'all' && item.action !== auditFilterAction.value) return false
    if (q) {
      const hay = `${item.user_email || ''} ${item.action || ''} ${item.target || ''} ${item.detail || ''} ${item.client_ip || item.ip || ''}`.toLowerCase()
      if (!hay.includes(q)) return false
    }
    return true
  })
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
    const res = await api.login(emailInput.value.trim(), passwordInput.value, totpInput.value.trim())
    passwordInput.value = ''
    totpInput.value = ''
    totpRequired.value = false
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
    authError.value = e.message || '登录失败'
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
    }
  } catch {
    // ignore
  }
  if (!token.value) return
  try {
    const [dash, nodeList, lineList, ruleList, planList, roleList] = await Promise.all([
      api.getDashboard(),
      api.getNodes(),
      api.getLines(),
      api.getRules(),
      api.getPlans(),
      api.getRoles().catch(() => []),
    ])
    user.value = dash.user
    hourlyStats.value = dash.hourly_stats || []
    globalHourlyStats.value = dash.global_hourly_stats || []
    topUsers.value = dash.top_users || []
    topNodes.value = dash.top_nodes || []
    nodes.value = nodeList
    lines.value = lineList
    rules.value = ruleList
    plans.value = planList
    rolesList.value = roleList
    if (dash.user.role === 'admin') {
      const [uList, adminCfg, rcList, ordList, aLogs] = await Promise.all([
        api.adminListUsers().catch(() => []),
        api.adminGetSettings().catch(() => null),
        api.adminListRedeemCodes().catch(() => []),
        api.getOrders({ all: true }).catch(() => []),
        api.adminListAuditLogs().catch(() => []),
      ])
      usersList.value = uList
      redeemCodesList.value = rcList
      ordersList.value = ordList
      auditLogsList.value = aLogs
      if (adminCfg) {
        siteConfig.value = adminCfg
        syncSettingsForm()
      }
    } else {
      ordersList.value = await api.getOrders().catch(() => [])
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
    .map((s) => s.trim())
    .filter(Boolean)
    .map((addr) => ({ address: addr }))

  const tun = getTunnelById(ruleForm.value.tunnel_line_id) || authorizedLines.value[0]
  if (!ruleForm.value.name || targets.length === 0 || !tun) {
    showToast('请填写完整信息')
    return
  }
  if (!userHasTunnel(user.value, tun.id)) {
    showToast('禁止越权使用未授权的隧道')
    return
  }

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
  try {
    if (editingLineId.value) {
      await api.adminUpdateLine(editingLineId.value, lineForm.value)
      showToast('隧道已更新')
    } else {
      await api.adminCreateLine(lineForm.value)
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
    port_range: nodeForm.value.port_range,
    traffic_rate: nodeForm.value.traffic_rate,
    quota_bytes: Math.max(0, Number(nodeForm.value.quota_gb) || 0) * GB,
    used_bytes: Math.max(0, Number(nodeForm.value.used_gb) || 0) * GB,
    reset_day: Math.min(28, Math.max(0, Number(nodeForm.value.reset_day) || 0)),
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
  if (
    !window.confirm(
      `确定花费 ¥${(p.price_cents / 100).toFixed(2)} 重置当前套餐「${p.name}」的订阅周期吗？\n这将立即清零已用流量、顺延 ${p.duration_days} 天有效期，并自动恢复因超额暂停的转发规则。`,
    )
  ) {
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
  const kw = redeemSearchKeyword.value.trim().toLowerCase()
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
  const unused = filteredRedeemCodes.value.filter((rc) => rc.used_by === 0).map((rc) => rc.code)
  if (unused.length === 0) {
    showToast('当前列表没有未使用的卡密')
    return
  }
  await copyConnectAddr(unused.join('\n'))
  showToast(`已复制 ${unused.length} 张未使用卡密`)
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
    if (order.pay_url) {
      window.open(order.pay_url, '_blank', 'noopener,noreferrer')
      showToast('已生成充值订单并打开支付页面')
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
    default:
      return tp
  }
}

async function handleBuyPlan(planId: number) {
  try {
    const res = await api.purchasePlan(planId)
    showToast(res.message)
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
  }
}

function getTunnelById(id: number): TunnelLine | undefined {
  return lines.value.find((l) => l.id === id)
}

// 规则实际运行引擎与配置引擎不同（限速规则从 gost/realm 回退到 native）
function ruleEngineFallback(rule: ForwardRule): boolean {
  return !!rule.effective_engine && rule.effective_engine !== (rule.engine || 'native')
}

function nodeNameById(id: number): string {
  return nodes.value.find((n) => n.id === id)?.name || `#${id}`
}

function nodeConnectIPById(id: number): string {
  const n = nodes.value.find((n) => n.id === id)
  return n ? n.connect_ip || n.public_host || n.server_ip : '127.0.0.1'
}

function userEmailById(uid: number): string {
  return usersList.value.find((u) => u.id === uid)?.email || `#${uid}`
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

function isAnyModalOpen(): boolean {
  return (
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
      if (t.user.expire_at !== undefined) user.value.expire_at = t.user.expire_at
      if (t.user.max_rules !== undefined) user.value.max_rules = t.user.max_rules
      if (t.user.speed_mbps !== undefined) user.value.speed_mbps = t.user.speed_mbps
      if (t.user.plan_id !== undefined) user.value.plan_id = t.user.plan_id
      if (t.user.role_group_id !== undefined) user.value.role_group_id = t.user.role_group_id
      if (t.user.allowed_tunnels !== undefined) user.value.allowed_tunnels = t.user.allowed_tunnels
    }
    if (Array.isArray(t.nodes)) {
      const nodeMap = new Map(nodes.value.map((n) => [n.id, n]))
      for (const nd of t.nodes) {
        if (!nd.id) continue
        const target = nodeMap.get(nd.id)
        if (target) {
          Object.assign(target, nd)
        }
      }
    }
    if (Array.isArray(t.rules)) {
      const ruleMap = new Map(rules.value.map((r) => [r.id, r]))
      for (const rd of t.rules) {
        const target = ruleMap.get(rd.id)
        if (target) {
          target.upload_bytes = rd.upload_bytes
          target.down_bytes = rd.down_bytes
          target.billed_bytes = rd.billed_bytes
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
  if (!document.hidden && autoRefresh.value && token.value) {
    pollTelemetryRealtime()
  }
}

function handleUnauthorized() {
  logout()
  showToast('登录已失效，请重新登录')
}

onMounted(() => {
  window.addEventListener('nexus-unauthorized', handleUnauthorized)
  refreshAll()
  telemetryTimer = setInterval(pollTelemetryRealtime, 3000)
  document.addEventListener('visibilitychange', handleVisibilityChange)
})

onUnmounted(() => {
  window.removeEventListener('nexus-unauthorized', handleUnauthorized)
  if (telemetryTimer) clearInterval(telemetryTimer)
  document.removeEventListener('visibilitychange', handleVisibilityChange)
})
</script>

<template>
  <div>
    <div v-if="toastMsg" class="toast">{{ toastMsg }}</div>

    <!-- 登录页 -->
    <div
      v-if="!token"
      style="min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 16px;"
    >
      <div class="card" style="width: 100%; max-width: 390px; padding: 28px;">
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 20px;">
          <div class="brand-logo">{{ siteConfig.site_logo || 'ZP' }}</div>
          <span style="font-size: 16px; font-weight: 600;">{{ siteConfig.site_name || 'Zachary Panel' }}</span>
        </div>

        <div style="display: flex; flex-direction: column; gap: 14px;">
          <div>
            <label class="form-label">邮箱</label>
            <input v-model="emailInput" type="email" class="input" autocomplete="username" />
          </div>
          <div>
            <label class="form-label">密码</label>
            <input v-model="passwordInput" type="password" class="input" autocomplete="current-password" @keyup.enter="handleAuth" />
          </div>
          <div v-if="totpRequired">
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
          <button @click="handleAuth" class="btn btn-primary" style="width: 100%; padding: 8px;">登录</button>
        </div>
      </div>
    </div>

    <div v-else class="app-shell">
      <aside class="sidebar">
        <div class="sidebar-brand">
          <div class="brand-logo">{{ siteConfig.site_logo || 'ZP' }}</div>
          <div class="brand-title-wrap">
            <span class="brand-title">{{ siteConfig.site_name || 'Zachary Panel' }}</span>
            <span class="brand-subtitle">Cloud Relay OS</span>
          </div>
        </div>

        <nav class="sidebar-nav">
          <div class="nav-group-label">业务中心</div>
          <button class="nav-item" :class="{ active: activeTab === 'dashboard' }" @click="activeTab = 'dashboard'">
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

          <button class="nav-item" :class="{ active: activeTab === 'rules' }" @click="activeTab = 'rules'">
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

          <button class="nav-item" :class="{ active: activeTab === 'store' }" @click="activeTab = 'store'">
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

          <template v-if="isAdmin">
            <div class="nav-group-label" style="margin-top: 8px;">基础设施</div>
            <button class="nav-item" :class="{ active: activeTab === 'lines' }" @click="activeTab = 'lines'">
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

            <button class="nav-item" :class="{ active: activeTab === 'nodes' }" @click="activeTab = 'nodes'">
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
            <button class="nav-item" :class="{ active: activeTab === 'roles' }" @click="activeTab = 'roles'">
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

            <button class="nav-item" :class="{ active: activeTab === 'users' }" @click="activeTab = 'users'">
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

            <button
              class="nav-item"
              :class="{ active: activeTab === 'settings' }"
              @click="activeTab = 'settings'; syncSettingsForm()"
            >
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
            <span style="font-weight: 700; color: #60a5fa;">{{ quotaPercent }}%</span>
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
            <span class="topbar-title">{{ currentTabTitle }}</span>
            <span class="topbar-pill">
              <span class="pulse-dot"></span>
              <span>实时同步</span>
            </span>
          </div>
          <div style="display: flex; align-items: center; gap: 10px;">
            <button @click="openPasswordModal" class="btn btn-soft btn-sm">修改密码</button>
            <button @click="toggleTheme" class="btn btn-outline btn-sm">{{ isDark ? '浅色' : '深色' }}</button>
            <div class="user-chip">
              <span class="user-avatar">{{ (user?.email || 'U').charAt(0) }}</span>
              <span style="font-size: 12.5px; font-weight: 600;">{{ user?.email }}</span>
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
                  <span class="badge" :class="node.status === 'online' ? 'badge-success' : 'badge-danger'">
                    <span class="dot"></span> {{ node.status === 'online' ? '在线' : '离线' }}
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
                    <th>类型</th>
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
                      <span class="badge" :class="line.type === 'encrypt' ? 'badge-purple' : 'badge-primary'">
                        {{ line.type === 'encrypt' ? '隧道转发' : '端口转发' }}
                      </span>
                    </td>
                    <td><span class="badge badge-neutral">{{ line.engine }}</span></td>
                    <td>{{ nodeConnectIPById(line.ingress_node_id) }}</td>
                    <td>{{ line.billing_mode === 'one_way' ? '单向' : '双向' }} · {{ line.rate_multiplier }}x</td>
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
                <button @click="openBatchModal" class="btn btn-soft">批量导入</button>
                <button @click="openCreateRuleModal" class="btn btn-primary">+ 新增转发</button>
              </div>
            </div>

            <!-- 规则搜索与多维筛选栏 -->
            <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
              <input
                v-model="ruleSearchQuery"
                class="input"
                style="width: 240px;"
                :placeholder="isAdmin ? '搜索规则名称 / 端口 / 目标 / 邮箱' : '搜索规则名称 / 端口 / 目标地址'"
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
              <select v-model="ruleFilterStatus" class="select" style="width: 120px;">
                <option value="all">全部状态</option>
                <option value="running">正常运行</option>
                <option value="paused">已暂停</option>
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
                        :disabled="filteredRules.length === 0"
                        @change="toggleSelectAllRules"
                        title="全选 / 取消全选"
                        style="cursor: pointer;"
                      />
                    </th>
                    <th>名称</th>
                    <th v-if="isAdmin">所属用户</th>
                    <th>隧道</th>
                    <th>转发方式</th>
                    <th>连接地址</th>
                    <th>目标地址</th>
                    <th>流量</th>
                    <th>状态</th>
                    <th style="text-align: right;">操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="rule in filteredRules" :key="rule.id">
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
                      <div style="font-size: 12px; color: var(--text-muted);">{{ rule.protocol.toUpperCase() }}</div>
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
                        :title="ruleEngineFallback(rule) ? '已设置限速，gost/realm 无法限速，实际以 native 引擎运行' : ''"
                      >
                        {{ rule.effective_engine || getTunnelById(rule.tunnel_line_id)?.engine || rule.engine }}
                        <template v-if="ruleEngineFallback(rule)">（限速回退）</template>
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
                        v-for="(t, idx) in parseTargets(rule.targets_json)"
                        :key="idx"
                        style="display: flex; align-items: center; gap: 6px;"
                      >
                        <span>{{ t.address }}</span>
                        <span
                          v-if="probeResults[rule.id]?.latencies?.[t.address] !== undefined"
                          class="badge"
                          :class="probeResults[rule.id].latencies[t.address] > 0 ? 'badge-success' : 'badge-danger'"
                        >
                          <template v-if="probeResults[rule.id].latencies[t.address] > 0">
                            {{
                              (probeResults[rule.id].tunnel_ms || 0) > 0
                                ? `隧道 ${probeResults[rule.id].tunnel_ms}ms + 落地 ${probeResults[rule.id].latencies[t.address]}ms`
                                : `${probeResults[rule.id].latencies[t.address]}ms`
                            }}
                          </template>
                          <template v-else>超时</template>
                        </span>
                      </div>
                    </td>
                    <td>{{ formatBytes(rule.billed_bytes) }}</td>
                    <td>
                      <span class="badge" :class="rule.enabled ? 'badge-success' : 'badge-neutral'">
                        <span class="dot"></span> {{ rule.enabled ? '正常' : '暂停' }}
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
                </tbody>
              </table>
            </div>
          </div>

          <!-- 隧道管理 (仅管理员) -->
          <div v-if="activeTab === 'lines' && isAdmin" style="display: flex; flex-direction: column; gap: 14px;">
            <div style="display: flex; justify-content: flex-end;">
              <button @click="openCreateLineModal" class="btn btn-primary">+ 新增隧道</button>
            </div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>名称</th>
                    <th>类型</th>
                    <th>转发方式</th>
                    <th>入口节点</th>
                    <th>出口节点</th>
                    <th>计费</th>
                    <th>规则数</th>
                    <th style="text-align: right;">操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="line in lines" :key="line.id">
                    <td style="font-weight: 500;">{{ line.name }}</td>
                    <td>
                      <span class="badge" :class="line.type === 'encrypt' ? 'badge-purple' : 'badge-primary'">
                        {{ line.type === 'encrypt' ? '隧道转发' : '端口转发' }}
                      </span>
                    </td>
                    <td><span class="badge badge-neutral">{{ line.engine }}</span></td>
                    <td>{{ nodeNameById(line.ingress_node_id) }}</td>
                    <td>
                      <span v-if="line.type === 'encrypt'">
                        {{ nodeNameById(line.egress_node_id) }} ({{ line.transport.toUpperCase() }})
                      </span>
                      <span v-else style="color: var(--text-muted);">-</span>
                    </td>
                    <td>{{ line.billing_mode === 'one_way' ? '单向' : '双向' }} · {{ line.rate_multiplier }}x</td>
                    <td>
                      {{ rules.filter((r) => r.tunnel_line_id === line.id).length }} / {{ line.max_port_count || 50 }}
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
                </tbody>
              </table>
            </div>
          </div>

          <!-- 节点管理 (仅管理员) -->
          <div v-if="activeTab === 'nodes' && isAdmin" style="display: flex; flex-direction: column; gap: 14px;">
            <div style="display: flex; justify-content: flex-end; gap: 8px;">
              <button @click="batchUpgradeOnlineNodes" class="btn btn-soft">一键升级在线节点</button>
              <button @click="openCreateNodeModal" class="btn btn-primary">+ 新增节点</button>
            </div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>名称 / 版本</th>
                    <th>连接地址</th>
                    <th>节点 IP</th>
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
                    <td style="color: var(--text-secondary);">{{ node.server_ip }}</td>
                    <td style="color: var(--text-secondary);">{{ node.port_range }}</td>
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
                      <span class="badge" :class="node.status === 'online' ? 'badge-success' : 'badge-danger'">
                        <span class="dot"></span> {{ node.status === 'online' ? '在线' : '离线' }}
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
                </tbody>
              </table>
            </div>
          </div>

          <!-- 角色管理 (仅管理员：角色决定可用哪些隧道) -->
          <div v-if="activeTab === 'roles' && isAdmin" style="display: flex; flex-direction: column; gap: 14px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
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
                    <td>{{ plans.filter((p) => p.role_group_id === rg.id).length }} 个套餐</td>
                    <td>{{ usersList.filter((u) => u.role !== 'admin' && u.role_group_id === rg.id).length }} 人</td>
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
                  <tr v-for="u in filteredUsersList" :key="u.id">
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
                </tbody>
              </table>
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

              <div class="table-wrap" style="max-height: 320px; overflow-y: auto;">
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
                    <tr v-for="rc in filteredRedeemCodes" :key="rc.id">
                      <td>
                        <button
                          @click="copyConnectAddr(rc.code)"
                          class="btn btn-soft btn-sm"
                          style="font-family: monospace; font-weight: 600;"
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
                      <td colspan="5" style="text-align: center; padding: 20px; color: var(--text-muted);">
                        暂无符合条件的兑换码记录
                      </td>
                    </tr>
                  </tbody>
                </table>
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
                  {{ user?.plan_id === plan.id ? '续费 / 重新激活该套餐' : '购买并激活套餐角色' }}
                </button>
              </div>
            </div>

            <!-- 账单与订单明细 -->
            <div class="card" style="display: flex; flex-direction: column; gap: 12px;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                  <div style="font-weight: 600; font-size: 14px;">{{ isAdmin ? '全站账单与充值订单明细' : '我的账单与充值记录' }}</div>
                  <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">
                    自动记录在线充值、套餐购买、周期重置与卡密核销流水
                  </div>
                </div>
                <button @click="openRechargeModal" class="btn btn-soft btn-sm">+ 创建充值订单</button>
              </div>

              <div class="table-wrap" style="max-height: 300px; overflow-y: auto;">
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
                    <tr v-for="ord in ordersList" :key="ord.id">
                      <td style="font-family: monospace; font-size: 12px;">{{ ord.order_no }}</td>
                      <td v-if="isAdmin" style="font-size: 12.5px;">{{ ord.user_email || '#' + ord.user_id }}</td>
                      <td>
                        <span class="badge badge-neutral">{{ orderTypeLabel(ord.type) }}</span>
                      </td>
                      <td style="font-size: 12.5px;">{{ ord.plan_name || '-' }}</td>
                      <td style="font-weight: 600;">¥{{ ((ord.amount_cents || 0) / 100).toFixed(2) }}</td>
                      <td style="font-size: 12px; color: var(--text-secondary);">{{ ord.gateway.toUpperCase() }}</td>
                      <td>
                        <span
                          class="badge"
                          :class="ord.status === 'paid' ? 'badge-success' : ord.status === 'pending' ? 'badge-primary' : 'badge-neutral'"
                        >
                          {{ ord.status === 'paid' ? '已入账' : ord.status === 'pending' ? '待支付' : '已取消' }}
                        </span>
                      </td>
                      <td style="font-size: 12px; color: var(--text-muted);">{{ formatDateDisplay(ord.created_at) }}</td>
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
                    <tr v-if="ordersList.length === 0">
                      <td :colspan="isAdmin ? 9 : 7" style="text-align: center; padding: 18px; color: var(--text-muted);">
                        暂无账单与订单记录
                      </td>
                    </tr>
                  </tbody>
                </table>
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
                  <span>开放新用户注册</span>
                </label>
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

              <div>
                <label class="form-label">USDT-TRC20 收款地址（选填，供加密货币或人工审核入账）</label>
                <input v-model="settingsForm.usdt_address" class="input" placeholder="T..." />
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
                <span style="font-weight: 600; font-size: 14px;">运维告警通知中心 (Telegram Bot / 通用 Webhook)</span>
                <div style="display: flex; gap: 16px; align-items: center;">
                  <label style="display: flex; align-items: center; gap: 6px; font-size: 13px; cursor: pointer;">
                    <input type="checkbox" v-model="settingsForm.notify_on_node_events" />
                    <span>节点上下线告警</span>
                  </label>
                  <label style="display: flex; align-items: center; gap: 6px; font-size: 13px; cursor: pointer;">
                    <input type="checkbox" v-model="settingsForm.notify_on_quota_events" />
                    <span>流量超额 / 套餐到期告警</span>
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

              <div class="table-wrap" style="max-height: 300px; overflow-y: auto;">
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
                    <tr v-for="log in filteredAuditLogs" :key="log.id">
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
                      <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 18px;">
                        暂无匹配的审计日志记录
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>

    <!-- 新增 / 编辑转发弹窗 (仅展示当前用户有权使用的隧道) -->
    <div v-if="showRuleModal" class="modal-backdrop" @click.self="showRuleModal = false">
      <div class="modal-box">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <span style="font-weight: 600;">{{ editingRuleId ? '编辑转发' : '新增转发' }}</span>
          <button @click="showRuleModal = false" class="btn btn-outline btn-sm">✕</button>
        </div>

        <div style="display: flex; flex-direction: column; gap: 12px;">
          <div>
            <label class="form-label">隧道</label>
            <select v-model="ruleForm.tunnel_line_id" class="select">
              <option v-for="l in authorizedLines" :key="l.id" :value="l.id">
                {{ l.name }} ({{ l.engine }})
              </option>
            </select>
          </div>

          <div>
            <label class="form-label">名称</label>
            <input v-model="ruleForm.name" class="input" placeholder="规则名称" />
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
              <label class="form-label">负载均衡</label>
              <select v-model="ruleForm.load_balance" class="select">
                <option value="round_robin">轮询</option>
                <option value="failover">主备</option>
              </select>
            </div>
          </div>

          <div>
            <label class="form-label">目标地址（多目标自动启用主动健康检查与故障剔除）</label>
            <textarea v-model="ruleForm.targetsText" rows="3" class="textarea" placeholder="每行一个 IP:端口"></textarea>
          </div>

          <div class="grid-2">
            <div>
              <label class="form-label">单规则限速 (Mbps，0=继承套餐限速)</label>
              <input v-model.number="ruleForm.speed_mbps" type="number" min="0" class="input" placeholder="0 为继承套餐限速" />
            </div>
            <div>
              <label class="form-label">来源 IP 访问控制 (ACL)</label>
              <select v-model="ruleForm.access_mode" class="select">
                <option value="off">关闭（允许所有来源 IP）</option>
                <option value="allow">白名单（仅允许指定 IP / CIDR）</option>
                <option value="deny">黑名单（拦截指定 IP / CIDR）</option>
              </select>
            </div>
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
            <button @click="submitRule" class="btn btn-primary">保存</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 新增 / 编辑隧道弹窗 -->
    <div v-if="showLineModal && isAdmin" class="modal-backdrop" @click.self="showLineModal = false">
      <div class="modal-box">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <span style="font-weight: 600;">{{ editingLineId ? '编辑隧道' : '新增隧道' }}</span>
          <button @click="showLineModal = false" class="btn btn-outline btn-sm">✕</button>
        </div>

        <div style="display: flex; flex-direction: column; gap: 12px;">
          <div class="grid-2">
            <div class="mode-card" :class="{ selected: lineForm.type === 'direct' }" @click="lineForm.type = 'direct'">
              端口转发
            </div>
            <div class="mode-card" :class="{ selected: lineForm.type === 'encrypt' }" @click="lineForm.type = 'encrypt'">
              隧道转发
            </div>
          </div>

          <div class="grid-2">
            <div>
              <label class="form-label">名称</label>
              <input v-model="lineForm.name" class="input" placeholder="隧道名称" />
            </div>
            <div>
              <label class="form-label">转发方式</label>
              <select v-model="lineForm.engine" class="select">
                <option value="realm">realm</option>
                <option value="gost">gost</option>
                <option value="nftables">nftables</option>
                <option value="native">native</option>
              </select>
            </div>
          </div>

          <div v-if="lineForm.type === 'direct'">
            <label class="form-label">入口节点</label>
            <select v-model="lineForm.ingress_node_id" class="select">
              <option v-for="n in nodes" :key="n.id" :value="n.id">{{ n.name }} ({{ n.connect_ip }})</option>
            </select>
          </div>

          <div v-else class="grid-3">
            <div>
              <label class="form-label">入口节点</label>
              <select v-model="lineForm.ingress_node_id" class="select">
                <option v-for="n in nodes" :key="n.id" :value="n.id">{{ n.name }}</option>
              </select>
            </div>
            <div>
              <label class="form-label">出口节点</label>
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
              该隧道的转发规则只在此范围内分配监听端口，格式如 20000-20999，需在入口节点端口范围之内；修改后对新分配的端口生效。
            </div>
          </div>

          <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px;">
            <button @click="showLineModal = false" class="btn btn-outline">取消</button>
            <button @click="submitLine" class="btn btn-primary">保存</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 新增 / 编辑节点弹窗 -->
    <div v-if="showNodeModal && isAdmin" class="modal-backdrop" @click.self="showNodeModal = false">
      <div class="modal-box">
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
              <label class="form-label">连接地址</label>
              <input v-model="nodeForm.connect_ip" class="input" placeholder="IP 或域名" />
            </div>
            <div>
              <label class="form-label">节点 IP</label>
              <input v-model="nodeForm.server_ip" class="input" placeholder="留空默认同连接地址" />
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
          <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px;">
            <button @click="showNodeModal = false" class="btn btn-outline">取消</button>
            <button @click="submitNode" class="btn btn-primary">保存</button>
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
            <div v-if="lastCreatedOrder.pay_url" style="margin-top: 6px;">
              <a :href="lastCreatedOrder.pay_url" target="_blank" rel="noopener noreferrer" class="btn btn-primary btn-sm">
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
  </div>
</template>
