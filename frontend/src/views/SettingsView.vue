<template>
  <div>
    <div class="page-header">
      <h2 class="page-title">系统设置</h2>
    </div>

    <div class="settings-grid">
      <!-- API Info -->
      <div class="card settings-card">
        <div class="settings-icon bg-blue">🔌</div>
        <div class="settings-body">
          <h3 class="settings-title">API 信息</h3>
          <div class="settings-row">
            <span class="settings-label">API Base</span>
            <code class="settings-code">/api</code>
          </div>
          <div class="settings-row">
            <span class="settings-label">Agent WebSocket</span>
            <code class="settings-code">/ws/agent</code>
          </div>
        </div>
      </div>

      <!-- User Info -->
      <div class="card settings-card">
        <div class="settings-icon bg-indigo">👤</div>
        <div class="settings-body">
          <h3 class="settings-title">当前用户</h3>
          <div class="settings-row">
            <span class="settings-label">用户名</span>
            <span class="settings-value">{{ auth.username }}</span>
          </div>
          <div class="settings-row">
            <span class="settings-label">登录状态</span>
            <span class="badge badge-success">已登录</span>
          </div>
        </div>
      </div>

      <!-- Token Info -->
      <div class="card settings-card col-span-2">
        <div class="settings-icon bg-purple">🔑</div>
        <div class="settings-body">
          <h3 class="settings-title">JWT Token</h3>
          <div class="token-box">
            <code>{{ tokenShort }}</code>
            <button @click="copyToken" class="btn btn-secondary btn-sm">{{ copyText }}</button>
          </div>
        </div>
      </div>

      <!-- Install Scripts -->
      <div class="card settings-card col-span-2">
        <div class="settings-icon bg-green">📜</div>
        <div class="settings-body">
          <h3 class="settings-title">安装脚本</h3>
          <div class="script-list">
            <div class="script-row">
              <span class="script-name">Agent 安装脚本</span>
              <code class="settings-code">{{ origin }}/install-agent.sh</code>
            </div>
            <div class="script-row">
              <span class="script-name">Server 安装脚本</span>
              <code class="settings-code">{{ origin }}/install-server.sh</code>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const token = auth.token
const copyText = ref('复制')

const tokenShort = computed(() => {
  if (!token) return '-'
  if (token.length <= 40) return token
  return token.slice(0, 20) + '...' + token.slice(-16)
})

const origin = computed(() => window.location.origin)

async function copyToken() {
  try {
    await navigator.clipboard.writeText(token)
    copyText.value = '已复制'
    setTimeout(() => copyText.value = '复制', 2000)
  } catch { /* ignore */ }
}
</script>

<style scoped>
.settings-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}
.col-span-2 { grid-column: span 2; }

.settings-card {
  padding: 1.25rem;
  display: flex;
  gap: 1rem;
}
.settings-icon {
  width: 44px;
  height: 44px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.125rem;
  flex-shrink: 0;
}

.settings-title { font-size: 0.875rem; font-weight: 600; margin: 0 0 0.75rem; }
.settings-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.25rem 0;
  font-size: 0.8125rem;
}
.settings-label { color: var(--color-text-muted); }
.settings-value { font-weight: 500; }
.settings-code {
  font-family: 'SF Mono', 'Fira Code', monospace;
  font-size: 0.75rem;
  background: #f1f5f9;
  padding: 0.125rem 0.375rem;
  border-radius: 4px;
  color: var(--color-text-secondary);
}

.token-box {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-top: 0.5rem;
}
.token-box code {
  flex: 1;
  font-family: 'SF Mono', monospace;
  font-size: 0.7rem;
  background: #f1f5f9;
  padding: 0.5rem 0.75rem;
  border-radius: 6px;
  color: var(--color-text-secondary);
  word-break: break-all;
}
.btn-sm { font-size: 0.7rem; padding: 0.25rem 0.5rem; }

.script-list { display: flex; flex-direction: column; gap: 0.5rem; }
.script-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.script-name { font-size: 0.8125rem; color: var(--color-text-secondary); }

@media (max-width: 768px) {
  .settings-grid { grid-template-columns: 1fr; }
  .col-span-2 { grid-column: span 1; }
}
</style>
