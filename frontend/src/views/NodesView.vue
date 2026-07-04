<template>
  <div class="nodes-page">
    <div class="page-header">
      <h2 class="text-lg font-semibold">节点管理</h2>
      <button @click="showCreate = true" class="btn-primary">+ 添加节点</button>
    </div>

    <!-- Empty state -->
    <div v-if="nodes.length === 0" class="empty-state">
      <div class="empty-icon">📡</div>
      <p class="empty-text">还没有节点，点击「添加节点」开始</p>
    </div>

    <!-- Node cards grid -->
    <div class="nodes-grid">
      <div v-for="n in nodes" :key="n.node_id" class="node-card" :class="{ offline: !isOnline(n) }">
        <!-- Card header -->
        <div class="card-header">
          <div class="card-title">
            <span class="status-dot" :class="statusDotClass(n.status)"></span>
            <span class="node-name">{{ n.name }}</span>
          </div>
          <div class="card-subtitle">
            <span v-if="n.hostname" class="hostname">{{ n.hostname }}</span>
            <span v-if="n.os" class="os-badge">{{ osIcon(n.os) }}</span>
            <span v-if="n.kernel" class="kernel-text">{{ n.kernel }}</span>
          </div>
          <div class="node-ip">{{ n.public_ip || n.last_ip || '-' }}</div>
        </div>

        <!-- Metrics -->
        <div class="metrics">
          <!-- CPU -->
          <div class="metric-row">
            <span class="metric-label">CPU</span>
            <div class="metric-bar-wrap">
              <div class="metric-bar" :style="{ width: pct(n.cpu_usage) + '%', background: barColor(n.cpu_usage) }"></div>
            </div>
            <span class="metric-value">{{ n.cpu_usage ? n.cpu_usage.toFixed(1) + '%' : '-' }}</span>
            <span class="metric-extra" v-if="n.cpu_cores">({{ n.cpu_cores }}核)</span>
          </div>

          <!-- Memory -->
          <div class="metric-row">
            <span class="metric-label">MEM</span>
            <div class="metric-bar-wrap">
              <div class="metric-bar" :style="{ width: memPct(n) + '%', background: barColor(memPct(n)) }"></div>
            </div>
            <span class="metric-value">{{ memPct(n).toFixed(0) }}%</span>
            <span class="metric-extra">{{ fmtMb(n.memory_used_mb) }}/{{ fmtMb(n.memory_total_mb) }}</span>
          </div>

          <!-- Disk -->
          <div class="metric-row">
            <span class="metric-label">DISK</span>
            <div class="metric-bar-wrap">
              <div class="metric-bar" :style="{ width: diskPct(n) + '%', background: barColor(diskPct(n)) }"></div>
            </div>
            <span class="metric-value">{{ diskPct(n).toFixed(0) }}%</span>
            <span class="metric-extra" v-if="n.disk_total_gb">{{ n.disk_used_gb?.toFixed(1) }}/{{ n.disk_total_gb?.toFixed(0) }}G</span>
          </div>

          <!-- Swap -->
          <div class="metric-row" v-if="n.swap_total_mb > 0">
            <span class="metric-label">SWAP</span>
            <div class="metric-bar-wrap">
              <div class="metric-bar" :style="{ width: swapPct(n) + '%', background: barColor(swapPct(n)) }"></div>
            </div>
            <span class="metric-value">{{ swapPct(n).toFixed(0) }}%</span>
            <span class="metric-extra">{{ fmtMb(n.swap_used_mb) }}/{{ fmtMb(n.swap_total_mb) }}</span>
          </div>
        </div>

        <!-- Network -->
        <div class="network-row" v-if="n.network_rx_bytes || n.network_tx_bytes">
          <span class="net-tx">↑ {{ formatBytes(n.network_tx_bytes) }}</span>
          <span class="net-rx">↓ {{ formatBytes(n.network_rx_bytes) }}</span>
        </div>

        <!-- Footer -->
        <div class="card-footer">
          <div class="agent-info">
            <span v-if="n.agent_version">Agent v{{ n.agent_version }}</span>
            <span v-if="n.gost_version"> gost {{ n.gost_version }}</span>
          </div>
          <div class="heartbeat-info">
            <span v-if="n.last_heartbeat_at">{{ relativeTime(n.last_heartbeat_at) }}</span>
            <span v-else class="text-slate-400">未连接</span>
          </div>
        </div>

        <!-- Actions -->
        <div class="card-actions">
          <router-link :to="`/nodes/${n.id}`" class="btn-link">详情</router-link>
          <button @click="getInstallCmd(n.id)" class="btn-link">安装命令</button>
          <button v-if="n.status !== 'disabled'" @click="disableNode(n.id)" class="btn-link btn-warn">禁用</button>
          <button v-else @click="enableNode(n.id)" class="btn-link btn-ok">启用</button>
        </div>
      </div>
    </div>

    <!-- Create Modal -->
    <div v-if="showCreate" class="modal-overlay" @click.self="showCreate = false">
      <div class="modal-box">
        <h3 class="modal-title">添加节点</h3>
        <div class="modal-form">
          <input v-model="form.name" placeholder="节点名称" class="input-field" />
          <input v-model="form.public_ip" placeholder="公网 IP（可选）" class="input-field" />
          <input v-model="form.remark" placeholder="备注（可选）" class="input-field" />
        </div>
        <div class="modal-actions">
          <button @click="showCreate = false" class="btn-secondary">取消</button>
          <button @click="createNode" class="btn-primary">创建</button>
        </div>
      </div>
    </div>

    <!-- Install Command Modal -->
    <div v-if="installCmd" class="modal-overlay" @click.self="installCmd = ''">
      <div class="modal-box modal-lg">
        <h3 class="modal-title">安装命令</h3>
        <p class="modal-hint">在目标节点上执行此命令</p>
        <div class="cmd-box">
          <pre class="cmd-text">{{ installCmd }}</pre>
          <button @click="copyInstallCmd" class="btn-copy">{{ copyBtnText }}</button>
        </div>
        <div class="modal-actions">
          <button @click="installCmd = ''" class="btn-primary">关闭</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { nodesApi } from '@/api/modules'

const nodes = ref<any[]>([])
const showCreate = ref(false)
const installCmd = ref('')
const form = ref({ name: '', public_ip: '', remark: '' })
const copyBtnText = ref('复制')
let refreshTimer: ReturnType<typeof setInterval> | null = null

onMounted(() => {
  load()
  // Auto-refresh every 5 seconds
  refreshTimer = setInterval(load, 5000)
})

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer)
})

async function load() {
  try {
    const res = await nodesApi.list({ page_size: 100 })
    nodes.value = res.data.data?.items || []
  } catch {
    // silent fail on refresh
  }
}

async function createNode() {
  await nodesApi.create(form.value)
  showCreate.value = false
  form.value = { name: '', public_ip: '', remark: '' }
  await load()
}

async function getInstallCmd(id: number) {
  const res = await nodesApi.installCommand(id)
  installCmd.value = res.data.data?.command || ''
}

async function disableNode(id: number) {
  // Use update API to set disabled status
  await nodesApi.update(id, { status: 'disabled' })
  await load()
}

async function enableNode(id: number) {
  await nodesApi.update(id, { status: 'offline' })
  await load()
}

async function copyInstallCmd() {
  try {
    await navigator.clipboard.writeText(installCmd.value)
    copyBtnText.value = '已复制'
    setTimeout(() => copyBtnText.value = '复制', 2000)
  } catch {
    const ta = document.createElement('textarea')
    ta.value = installCmd.value
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    document.body.removeChild(ta)
    copyBtnText.value = '已复制'
    setTimeout(() => copyBtnText.value = '复制', 2000)
  }
}

// ── Formatting helpers ──

function isOnline(n: any): boolean {
  return n.status === 'online'
}

function statusDotClass(status: string): string {
  switch (status) {
    case 'online': return 'dot-online'
    case 'offline': return 'dot-offline'
    case 'disabled': return 'dot-disabled'
    case 'error': return 'dot-error'
    default: return 'dot-offline'
  }
}

function osIcon(os: string): string {
  if (!os) return ''
  const lower = os.toLowerCase()
  if (lower.includes('linux')) return '🐧 Linux'
  if (lower.includes('windows')) return '🪟 Windows'
  if (lower.includes('darwin') || lower.includes('mac')) return '🍎 macOS'
  if (lower.includes('freebsd')) return '👹 FreeBSD'
  return '💻 ' + os
}

function pct(v: number): number {
  return Math.min(100, Math.max(0, v || 0))
}

function memPct(n: any): number {
  if (!n.memory_total_mb || n.memory_total_mb === 0) return 0
  return (n.memory_used_mb / n.memory_total_mb) * 100
}

function diskPct(n: any): number {
  if (!n.disk_total_gb || n.disk_total_gb === 0) return 0
  return ((n.disk_used_gb || 0) / n.disk_total_gb) * 100
}

function swapPct(n: any): number {
  if (!n.swap_total_mb || n.swap_total_mb === 0) return 0
  return (n.swap_used_mb / n.swap_total_mb) * 100
}

function barColor(p: number): string {
  if (p > 90) return '#ef4444'
  if (p > 70) return '#f59e0b'
  return '#22c55e'
}

function formatBytes(bytes: number): string {
  if (!bytes || bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = bytes
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return v < 10 ? `${v.toFixed(1)} ${units[i]}` : `${v.toFixed(0)} ${units[i]}`
}

function fmtMb(mb: number): string {
  if (!mb) return '0M'
  if (mb >= 1024) return `${(mb / 1024).toFixed(1)}G`
  return `${mb}M`
}

function relativeTime(ts: string): string {
  if (!ts) return '-'
  try {
    const date = new Date(ts.includes('T') ? ts : ts.replace(' ', 'T') + 'Z')
    const now = Date.now()
    const diff = Math.floor((now - date.getTime()) / 1000)
    if (diff < 0) return '刚刚'
    if (diff < 60) return `${diff}秒前`
    if (diff < 3600) return `${Math.floor(diff / 60)}分钟前`
    if (diff < 86400) return `${Math.floor(diff / 3600)}小时前`
    return `${Math.floor(diff / 86400)}天前`
  } catch {
    return ts
  }
}
</script>

<style scoped>
.nodes-page {
  padding: 0;
}

.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1.5rem;
}

/* ── Grid ── */
.nodes-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
  gap: 1rem;
}

/* ── Empty state ── */
.empty-state {
  text-align: center;
  padding: 4rem 1rem;
  color: #94a3b8;
}
.empty-icon { font-size: 3rem; margin-bottom: 0.5rem; }
.empty-text { font-size: 0.875rem; }

/* ── Card ── */
.node-card {
  background: white;
  border-radius: 12px;
  padding: 1.25rem;
  box-shadow: 0 1px 3px rgba(0,0,0,0.08);
  border: 1px solid #f1f5f9;
  transition: box-shadow 0.2s;
}
.node-card:hover { box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
.node-card.offline { opacity: 0.55; }

/* ── Card header ── */
.card-header { margin-bottom: 1rem; }
.card-title {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.25rem;
}
.status-dot {
  width: 8px; height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.dot-online { background: #22c55e; box-shadow: 0 0 6px #22c55e88; }
.dot-offline { background: #94a3b8; }
.dot-disabled { background: #f59e0b; }
.dot-error { background: #ef4444; }

.node-name { font-weight: 600; font-size: 1rem; }

.card-subtitle {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.75rem;
  color: #64748b;
  margin-bottom: 0.125rem;
}
.hostname { font-weight: 500; }
.kernel-text { color: #94a3b8; }
.os-badge { font-size: 0.7rem; }

.node-ip {
  font-size: 0.75rem;
  color: #94a3b8;
  font-family: monospace;
}

/* ── Metrics ── */
.metrics { display: flex; flex-direction: column; gap: 0.5rem; margin-bottom: 0.75rem; }
.metric-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.75rem;
}
.metric-label {
  width: 36px;
  color: #64748b;
  font-weight: 500;
  flex-shrink: 0;
}
.metric-bar-wrap {
  flex: 1;
  height: 8px;
  background: #f1f5f9;
  border-radius: 4px;
  overflow: hidden;
}
.metric-bar {
  height: 100%;
  border-radius: 4px;
  transition: width 0.5s ease;
}
.metric-value {
  width: 40px;
  text-align: right;
  font-variant-numeric: tabular-nums;
  font-weight: 500;
  flex-shrink: 0;
}
.metric-extra {
  color: #94a3b8;
  font-size: 0.7rem;
  width: 70px;
  text-align: right;
  flex-shrink: 0;
}

/* ── Network ── */
.network-row {
  display: flex;
  gap: 1rem;
  font-size: 0.75rem;
  color: #64748b;
  margin-bottom: 0.75rem;
  padding-top: 0.5rem;
  border-top: 1px solid #f8fafc;
}

/* ── Footer ── */
.card-footer {
  display: flex;
  justify-content: space-between;
  font-size: 0.7rem;
  color: #94a3b8;
  margin-bottom: 0.75rem;
}

/* ── Actions ── */
.card-actions {
  display: flex;
  gap: 0.75rem;
  padding-top: 0.75rem;
  border-top: 1px solid #f8fafc;
}

/* ── Buttons ── */
.btn-primary {
  background: #3b82f6;
  color: white;
  font-size: 0.875rem;
  padding: 0.375rem 0.75rem;
  border-radius: 8px;
  border: none;
  cursor: pointer;
  transition: background 0.2s;
}
.btn-primary:hover { background: #2563eb; }

.btn-secondary {
  font-size: 0.875rem;
  padding: 0.375rem 0.75rem;
  border-radius: 8px;
  border: 1px solid #e2e8f0;
  background: white;
  cursor: pointer;
}
.btn-secondary:hover { background: #f8fafc; }

.btn-link {
  font-size: 0.75rem;
  color: #3b82f6;
  background: none;
  border: none;
  cursor: pointer;
  text-decoration: none;
  padding: 0;
}
.btn-link:hover { text-decoration: underline; }
.btn-warn { color: #f59e0b; }
.btn-ok { color: #22c55e; }

/* ── Modal ── */
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.4);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 50;
}
.modal-box {
  background: white;
  border-radius: 12px;
  padding: 1.5rem;
  width: 100%;
  max-width: 28rem;
}
.modal-lg { max-width: 36rem; }
.modal-title { font-size: 1.125rem; font-weight: 600; margin-bottom: 0.75rem; }
.modal-hint { font-size: 0.875rem; color: #64748b; margin-bottom: 0.75rem; }
.modal-form { display: flex; flex-direction: column; gap: 0.75rem; margin-bottom: 1rem; }
.modal-actions { display: flex; justify-content: flex-end; gap: 0.5rem; }

.input-field {
  width: 100%;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 0.5rem 0.75rem;
  font-size: 0.875rem;
}
.input-field:focus { outline: none; border-color: #3b82f6; }

.cmd-box { position: relative; }
.cmd-text {
  background: #0f172a;
  color: #4ade80;
  border-radius: 8px;
  padding: 0.75rem;
  font-size: 0.8125rem;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
}
.btn-copy {
  position: absolute;
  top: 0.5rem;
  right: 0.5rem;
  background: #334155;
  color: white;
  font-size: 0.7rem;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  border: none;
  cursor: pointer;
}
.btn-copy:hover { background: #475569; }
</style>
