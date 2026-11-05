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

// --- 规则批量导入与导出 ---
const showBatchModal = ref(false)
const batchForm = ref({
  tunnel_line_id: 1,
  protocol: 'tcp' as 'tcp' | 'udp' | 'both',
  rawText: '业务节点A|0|1.1.1.1:443\n业务节点B|0|8.8.8.8:53',
})

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

async function submitBatchRules() {
  if (!userHasTunnel(user.value, batchForm.value.tunnel_line_id)) {
    showToast('无权在该隧道下导入规则')
    return
  }
  const rows = batchForm.value.rawText
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean)
  const items = rows
    .map((row, idx) => {
      const parts = row.split('|').map((s) => s.trim())
      if (parts.length < 2) return null
      const name = parts.length >= 3 ? parts[0] : `批量规则-${idx + 1}`
      const listen_port = parts.length >= 3 ? Number(parts[1]) || 0 : Number(parts[0]) || 0
      const addr = parts.length >= 3 ? parts[2] : parts[1]
      return { name, listen_port, targets: [{ address: addr }] }
    })
    .filter(Boolean) as Array<{ name: string; listen_port: number; targets: TargetEndpoint[] }>

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
  const text = visibleRules.value
    .map((r) => {
      const firstTarget = parseTargets(r.targets_json)[0]?.address || ''
      return `${r.name}|${r.listen_port}|${firstTarget}`
    })
    .join('\n')
  copyConnectAddr(text)
  showToast(`已导出 ${visibleRules.value.length} 条规则到剪贴板`)
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
  max_rules: 20,
  speed_mbps: 100,
})

function onUserPlanChange() {
  const p = plans.value.find((x) => x.id === Number(userForm.value.plan_id))
  if (p) {
    if (p.role_group_id) userForm.value.role_group_id = p.role_group_id
    userForm.value.quota_gb = Math.round((p.quota_bytes || 0) / GB)
    userForm.value.max_rules = p.max_rules
    userForm.value.speed_mbps = p.speed_mbps
  }
}

function openCreateUserModal() {
  if (!isAdmin.value) return
  editingUserId.value = null
  const defPlan = plans.value[0]
  userForm.value = {
    id: 0,
    email: '',
    password: '',
    role: 'user',
    plan_id: defPlan?.id || 1,
    role_group_id: defPlan?.role_group_id || siteConfig.value.default_role_group_id || rolesList.value[0]?.id || 1,
    quota_gb: defPlan ? Math.round(defPlan.quota_bytes / GB) : siteConfig.value.default_quota_gb || 20,
    used_gb: 0,
    max_rules: defPlan ? defPlan.max_rules : siteConfig.value.default_max_rules || 5,
    speed_mbps: defPlan ? defPlan.speed_mbps : siteConfig.value.default_speed_mbps || 100,
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
    max_rules: u.max_rules,
    speed_mbps: u.speed_mbps,
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
        used_bytes: Math.max(0, Number(userForm.value.used_gb) || 0) * GB,
        max_rules: userForm.value.max_rules,
        speed_mbps: userForm.value.speed_mbps,
        allowed_tunnels: allowedStr,
        password: userForm.value.password || undefined,
      })
      showToast('用户的套餐、角色与配额已保存')
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
        allowed_tunnels: allowedStr,
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
    })
    siteConfig.value = updated
    document.title = siteConfig.value.site_name
    showToast('面板基础配置已保存')
  } catch (e: any) {
    showToast(e.message)
  }
}

const quotaPercent = computed(() => {
  if (!user.value || !user.value.quota_bytes) return 0
  return Math.min(100, Number(((user.value.used_bytes / user.value.quota_bytes) * 100).toFixed(1)))
})

// 修改密码
const showPasswordModal = ref(false)
const pwdForm = ref({ old: '', next: '', confirm: '' })
const pwdError = ref('')

function openPasswordModal() {
  pwdForm.value = { old: '', next: '', confirm: '' }
  pwdError.value = ''
  showPasswordModal.value = true
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
    const res = await api.login(emailInput.value.trim(), passwordInput.value)
    passwordInput.value = ''
    localStorage.setItem('nexus_token', res.token)
    token.value = res.token
    user.value = res.user
    if (res.user.role !== 'admin' && ['lines', 'nodes', 'roles', 'users', 'settings'].includes(activeTab.value)) {
      activeTab.value = 'dashboard'
    }
    await refreshAll()
  } catch (e: any) {
    authError.value = e.message || '登录失败'
  }
}

function logout() {
  localStorage.removeItem('nexus_token')
  token.value = null
  user.value = null
}

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
    nodes.value = nodeList
    lines.value = lineList
    rules.value = ruleList
    plans.value = planList
    rolesList.value = roleList
    if (dash.user.role === 'admin') {
      const [uList, adminCfg] = await Promise.all([
        api.adminListUsers().catch(() => []),
        api.adminGetSettings().catch(() => null),
      ])
      usersList.value = uList
      if (adminCfg) {
        siteConfig.value = adminCfg
        syncSettingsForm()
      }
    } else if (['lines', 'nodes', 'roles', 'users', 'settings'].includes(activeTab.value)) {
      activeTab.value = 'dashboard'
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

async function handleRedeem() {
  try {
    const res = await api.redeemCode(redeemInput.value)
    showToast(res.message)
    await refreshAll()
  } catch (e: any) {
    showToast(e.message)
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
    showUserModal.value
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
            <div style="display: flex; justify-content: space-between; align-items: center;">
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
              <div style="display: flex; gap: 8px;">
                <button @click="exportRulesToClipboard" class="btn btn-outline">导出规则</button>
                <button @click="openBatchModal" class="btn btn-soft">批量导入</button>
                <button @click="openCreateRuleModal" class="btn btn-primary">+ 新增转发</button>
              </div>
            </div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
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
                  <tr v-for="rule in visibleRules" :key="rule.id">
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
                      <span class="badge badge-neutral">
                        {{ getTunnelById(rule.tunnel_line_id)?.engine || rule.engine }}
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
            <div style="display: flex; justify-content: flex-end;">
              <button @click="openCreateNodeModal" class="btn btn-primary">+ 新增节点</button>
            </div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>名称</th>
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
                    <td style="font-weight: 500;">{{ node.name }}</td>
                    <td>
                      <button class="copy-pill" @click="copyConnectAddr(node.connect_ip || node.public_host)">
                        {{ node.connect_ip || node.public_host }}
                      </button>
                    </td>
                    <td style="color: var(--text-secondary);">{{ node.server_ip }}</td>
                    <td style="color: var(--text-secondary);">{{ node.port_range }}</td>
                    <td>{{ node.traffic_rate || 1 }}x</td>
                    <td>
                      {{ formatBytes(node.used_bytes) }} /
                      {{ node.quota_bytes > 0 ? formatBytes(node.quota_bytes) : '不限' }}
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
                      <button @click="resyncNodeRules(node)" class="btn btn-outline btn-sm" style="margin-right: 4px;">
                        同步
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
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="font-size: 12.5px; color: var(--text-secondary);">
                为用户分配套餐与角色，用户的可用隧道由其所属角色决定。
              </span>
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
                    <th>状态</th>
                    <th style="text-align: right;">操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="u in usersList" :key="u.id">
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
                    <td>
                      <span class="badge" :class="u.status === 'active' ? 'badge-success' : 'badge-danger'">
                        <span class="dot"></span> {{ u.status === 'active' ? '正常' : '已封禁' }}
                      </span>
                    </td>
                    <td style="text-align: right; white-space: nowrap;">
                      <button @click="openEditUserModal(u)" class="btn btn-soft btn-sm" style="margin-right: 4px;">
                        分配套餐/角色
                      </button>
                      <button @click="resetUserTraffic(u)" class="btn btn-outline btn-sm" style="margin-right: 4px;">
                        重置流量
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
            <div style="display: flex; justify-content: space-between; align-items: center; gap: 10px; flex-wrap: wrap;">
              <div style="display: flex; align-items: center; gap: 8px;">
                <input v-model="redeemInput" class="input" style="width: 240px;" placeholder="输入兑换码" />
                <button @click="handleRedeem" class="btn btn-soft">兑换套餐</button>
              </div>
              <button v-if="isAdmin" @click="openCreatePlanModal" class="btn btn-primary">+ 新增套餐</button>
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
          </div>

          <!-- 系统设置 (仅管理员) -->
          <div v-if="activeTab === 'settings' && isAdmin" style="max-width: 680px;">
            <div class="card" style="display: flex; flex-direction: column; gap: 14px;">
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

              <div style="display: flex; justify-content: flex-end; margin-top: 4px;">
                <button @click="saveSystemSettings" class="btn btn-primary">保存配置</button>
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
              <input v-model.number="ruleForm.listen_port" type="number" class="input" placeholder="留空自动分配" />
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
            <label class="form-label">目标地址</label>
            <textarea v-model="ruleForm.targetsText" rows="3" class="textarea" placeholder="每行一个 IP:端口"></textarea>
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
          <div class="grid-2">
            <div>
              <label class="form-label">流量限额 (GB)</label>
              <input v-model.number="nodeForm.quota_gb" type="number" step="1" class="input" placeholder="0 为不限" />
            </div>
            <div>
              <label class="form-label">已用流量 (GB)</label>
              <input v-model.number="nodeForm.used_gb" type="number" step="0.1" class="input" />
            </div>
          </div>
          <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px;">
            <button @click="showNodeModal = false" class="btn btn-outline">取消</button>
            <button @click="submitNode" class="btn btn-primary">保存</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 修改密码弹窗 -->
    <div v-if="showPasswordModal" class="modal-backdrop" @click.self="showPasswordModal = false">
      <div class="modal-box" style="max-width: 420px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
          <span style="font-weight: 600;">修改密码</span>
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
          <button @click="submitChangePassword" class="btn btn-primary" style="width: 100%;">确认修改</button>
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
            <label class="form-label">规则列表</label>
            <textarea v-model="batchForm.rawText" rows="5" class="textarea" placeholder="格式：名称|监听端口|目标IP:端口"></textarea>
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
              <input v-model="userForm.password" type="password" class="input" placeholder="至少6位" />
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

          <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px;">
            <button @click="showUserModal = false" class="btn btn-outline">取消</button>
            <button @click="submitUserEdit" class="btn btn-primary">保存</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
