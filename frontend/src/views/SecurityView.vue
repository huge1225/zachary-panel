<template>
  <div>
    <div class="page-header">
      <h2 class="page-title">安全事件</h2>
    </div>

    <div class="card">
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>时间</th>
              <th>级别</th>
              <th>类型</th>
              <th>节点</th>
              <th>消息</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="e in events" :key="e.id">
              <td style="color: var(--color-text-muted); font-size: 0.75rem; white-space: nowrap;">{{ e.created_at }}</td>
              <td><span class="badge" :class="severityClass(e.severity)">{{ severityLabel(e.severity) }}</span></td>
              <td><span style="font-weight: 500;">{{ typeLabel(e.event_type) }}</span></td>
              <td>
                <span v-if="e.node_name" style="font-weight: 500;">{{ e.node_name }}</span>
                <span v-else style="color: var(--color-text-muted); font-size: 0.75rem; font-family: monospace;">{{ e.node_id || '-' }}</span>
              </td>
              <td style="font-size: 0.75rem; color: var(--color-text-secondary);">{{ e.message }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="!events.length" class="empty-state">
        <div class="empty-icon">🛡️</div>
        <p class="empty-text">暂无安全事件 🎉</p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { securityApi } from '@/api/modules'

const events = ref<any[]>([])

onMounted(async () => {
  const res = await securityApi.list({ page_size: 50 })
  events.value = res.data.data?.items || []
})

function severityClass(s: string) {
  switch (s) {
    case 'critical': return 'badge-danger'
    case 'warning': return 'badge-warning'
    case 'info': return 'badge-info'
    default: return 'badge-neutral'
  }
}

function severityLabel(s: string) {
  const map: Record<string, string> = {
    critical: '严重',
    warning: '警告',
    info: '信息',
  }
  return map[s] || s
}

function typeLabel(t: string) {
  const map: Record<string, string> = {
    'agent_auth_fail': '认证失败',
    'token_expired': '令牌过期',
    'replay_detected': '重放检测',
    'unauthorized_access': '未授权访问',
    'agent_signature_fail': '签名验证失败',
  }
  return map[t] || t
}
</script>

<style scoped>
.table-wrap { overflow-x: auto; }
.empty-state { text-align: center; padding: 3rem 1rem; }
.empty-icon { font-size: 2.5rem; margin-bottom: 0.5rem; }
.empty-text { color: var(--color-text-muted); font-size: 0.875rem; margin: 0; }
</style>
