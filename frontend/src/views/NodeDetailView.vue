<template>
  <div>
    <!-- Back link -->
    <router-link to="/nodes" class="back-link">← 返回节点列表</router-link>

    <div v-if="node" class="detail-grid">
      <!-- Summary card -->
      <div class="card detail-summary">
        <div class="summary-header">
          <div class="summary-left">
            <span class="status-dot" :class="statusDotClass(node.status)"></span>
            <h2 class="summary-name">{{ node.name }}</h2>
          </div>
          <span class="badge" :class="statusClass(node.status)">{{ statusLabel(node.status) }}</span>
        </div>
        <div class="summary-ip">{{ node.public_ip || node.last_ip || '-' }}</div>
        <div v-if="node.remark" class="summary-remark">{{ node.remark }}</div>
      </div>

      <!-- System info -->
      <div class="card detail-card">
        <div class="card-title">系统信息</div>
        <div class="detail-list">
          <div class="detail-row">
            <span class="detail-label">Node ID</span>
            <span class="detail-value mono">{{ node.node_id }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">操作系统</span>
            <span class="detail-value">{{ node.os || '-' }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">架构</span>
            <span class="detail-value">{{ node.arch || '-' }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">内核</span>
            <span class="detail-value">{{ node.kernel || '-' }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">主机名</span>
            <span class="detail-value">{{ node.hostname || '-' }}</span>
          </div>
        </div>
      </div>

      <!-- Agent info -->
      <div class="card detail-card">
        <div class="card-title">Agent 状态</div>
        <div class="detail-list">
          <div class="detail-row">
            <span class="detail-label">Agent 版本</span>
            <span class="detail-value">{{ node.agent_version || '-' }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">gost 版本</span>
            <span class="detail-value">{{ node.gost_version || '-' }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">nftables</span>
            <span class="detail-value"><span class="badge" :class="node.nft_status === 'ok' ? 'badge-success' : 'badge-warning'">{{ node.nft_status }}</span></span>
          </div>
          <div class="detail-row">
            <span class="detail-label">gost</span>
            <span class="detail-value"><span class="badge" :class="node.gost_status === 'ok' ? 'badge-success' : 'badge-warning'">{{ node.gost_status }}</span></span>
          </div>
          <div class="detail-row">
            <span class="detail-label">最后心跳</span>
            <span class="detail-value">{{ node.last_heartbeat_at || '-' }}</span>
          </div>
        </div>
      </div>

      <!-- Security -->
      <div class="card detail-card">
        <div class="card-title">安全</div>
        <div class="detail-list">
          <div class="detail-row">
            <span class="detail-label">TLS 验证</span>
            <span class="detail-value"><span class="badge" :class="node.tls_verify ? 'badge-success' : 'badge-danger'">{{ node.tls_verify ? '已启用' : '未启用' }}</span></span>
          </div>
          <div class="detail-row">
            <span class="detail-label">TLS Pinning</span>
            <span class="detail-value"><span class="badge" :class="node.tls_pinning ? 'badge-success' : 'badge-neutral'">{{ node.tls_pinning ? '已启用' : '未启用' }}</span></span>
          </div>
          <div class="detail-row">
            <span class="detail-label">最后 IP</span>
            <span class="detail-value mono">{{ node.last_ip || '-' }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">创建时间</span>
            <span class="detail-value">{{ node.created_at || '-' }}</span>
          </div>
        </div>
      </div>

      <!-- Quick actions -->
      <div class="card detail-card col-span-full">
        <div class="card-title">快捷操作</div>
        <div class="action-grid">
          <button @click="getInstallCmd" class="action-card">
            <span class="action-icon">📥</span>
            <span class="action-label">安装命令</span>
          </button>
          <button v-if="node.status !== 'disabled'" @click="disableNode" class="action-card">
            <span class="action-icon">🚫</span>
            <span class="action-label">禁用节点</span>
          </button>
          <button v-else @click="enableNode" class="action-card">
            <span class="action-icon">✅</span>
            <span class="action-label">启用节点</span>
          </button>
          <button @click="deleteNode" class="action-card action-danger">
            <span class="action-icon">🗑</span>
            <span class="action-label">删除节点</span>
          </button>
        </div>
      </div>
    </div>

    <div v-else class="loading-state">
      <div class="skeleton" style="width: 100%; height: 100px;"></div>
    </div>

    <!-- Install Command Modal -->
    <div v-if="installCmd" class="modal-overlay" @click.self="installCmd = ''">
      <div class="modal-box modal-lg">
        <h3 class="modal-title">安装命令</h3>
        <p style="font-size: 0.8125rem; color: var(--color-text-muted); margin-bottom: 0.75rem;">在目标节点上执行此命令</p>
        <div style="position: relative;">
          <pre style="background: #0f172a; color: #4ade80; border-radius: 8px; padding: 0.75rem; font-size: 0.8125rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all;">{{ installCmd }}</pre>
          <button @click="copyCmd" style="position: absolute; top: 0.5rem; right: 0.5rem; background: #334155; color: white; font-size: 0.7rem; padding: 0.25rem 0.5rem; border-radius: 4px; border: none; cursor: pointer;">{{ copyText }}</button>
        </div>
        <div style="display: flex; justify-content: flex-end; margin-top: 1rem;">
          <button @click="installCmd = ''" class="btn btn-primary">关闭</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { nodesApi } from '@/api/modules'

const route = useRoute()
const router = useRouter()
const node = ref<any>(null)
const installCmd = ref('')
const copyText = ref('复制')

onMounted(async () => {
  const id = Number(route.params.id)
  const res = await nodesApi.get(id)
  node.value = res.data.data
})

function statusClass(status: string) {
  switch (status) {
    case 'online': return 'badge-success'
    case 'offline': return 'badge-neutral'
    case 'disabled': return 'badge-warning'
    case 'error': return 'badge-danger'
    default: return 'badge-neutral'
  }
}

function statusDotClass(status: string) {
  switch (status) {
    case 'online': return 'dot-green'
    case 'disabled': return 'dot-yellow'
    case 'error': return 'dot-red'
    default: return 'dot-gray'
  }
}

function statusLabel(s: string) {
  const map: Record<string, string> = {
    online: '在线',
    offline: '离线',
    disabled: '已禁用',
    error: '错误',
  }
  return map[s] || s
}

async function getInstallCmd() {
  const res = await nodesApi.installCommand(node.value.id)
  installCmd.value = res.data.data?.command || ''
}

async function copyCmd() {
  try {
    await navigator.clipboard.writeText(installCmd.value)
    copyText.value = '已复制'
    setTimeout(() => copyText.value = '复制', 2000)
  } catch { /* ignore */ }
}

async function disableNode() {
  if (!confirm('确定禁用此节点？')) return
  await nodesApi.disable(node.value.id)
  const res = await nodesApi.get(node.value.id)
  node.value = res.data.data
}

async function enableNode() {
  await nodesApi.enable(node.value.id)
  const res = await nodesApi.get(node.value.id)
  node.value = res.data.data
}

async function deleteNode() {
  if (!confirm('确定删除此节点？此操作不可撤销。')) return
  await nodesApi.delete(node.value.id)
  router.push('/nodes')
}
</script>

<style scoped>
.back-link {
  display: inline-block;
  font-size: 0.8125rem;
  color: var(--color-primary);
  text-decoration: none;
  margin-bottom: 1rem;
}
.back-link:hover { text-decoration: underline; }

.detail-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}
.col-span-full { grid-column: 1 / -1; }

.detail-summary {
  padding: 1.25rem;
  grid-column: 1 / -1;
}
.summary-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.summary-left {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.summary-name { font-size: 1.25rem; font-weight: 700; margin: 0; }
.summary-ip { font-size: 0.875rem; color: var(--color-text-muted); font-family: monospace; margin-top: 0.25rem; }
.summary-remark { font-size: 0.8125rem; color: var(--color-text-secondary); margin-top: 0.25rem; }

.detail-card { padding: 1.25rem; }
.card-title {
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--color-text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 0.75rem;
}

.detail-list { display: flex; flex-direction: column; gap: 0.5rem; }
.detail-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 0.8125rem;
}
.detail-label { color: var(--color-text-muted); }
.detail-value { font-weight: 500; }
.mono { font-family: 'SF Mono', monospace; font-size: 0.75rem; }

.action-grid {
  display: flex;
  gap: 0.625rem;
  flex-wrap: wrap;
}
.action-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.375rem;
  padding: 0.875rem 1.25rem;
  border: 1px solid var(--color-border);
  border-radius: 10px;
  background: white;
  cursor: pointer;
  transition: all 0.15s;
  min-width: 100px;
}
.action-card:hover {
  border-color: var(--color-primary);
  background: #eff6ff;
}
.action-danger:hover {
  border-color: var(--color-danger);
  background: #fef2f2;
}
.action-icon { font-size: 1.25rem; }
.action-label { font-size: 0.75rem; font-weight: 500; }

.loading-state { padding: 1rem 0; }

.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(15, 23, 42, 0.5);
  backdrop-filter: blur(4px);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 50;
}
.modal-box {
  background: white;
  border-radius: 14px;
  padding: 1.5rem;
  width: 100%;
  max-width: 28rem;
  box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1);
}
.modal-lg { max-width: 40rem; }
.modal-title { font-size: 1rem; font-weight: 600; margin: 0 0 0.5rem; }

@media (max-width: 768px) {
  .detail-grid { grid-template-columns: 1fr; }
}
</style>
