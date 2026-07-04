<template>
  <div>
    <div class="page-header">
      <h2 class="page-title">任务列表</h2>
    </div>

    <div class="card">
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>类型</th>
              <th>节点</th>
              <th>状态</th>
              <th>结果信息</th>
              <th>创建时间</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="t in tasks" :key="t.task_id">
              <td>
                <span class="task-type" :class="typeClass(t.type)">{{ typeLabel(t.type) }}</span>
              </td>
              <td>
                <div style="display: flex; flex-direction: column; gap: 2px;">
                  <span style="font-weight: 500;">{{ t.node_name || t.node_id }}</span>
                  <span style="font-size: 0.7rem; color: var(--color-text-muted); font-family: monospace;">{{ t.node_id }}</span>
                </div>
              </td>
              <td><span class="badge" :class="taskStatusClass(t.status)">{{ statusLabel(t.status) }}</span></td>
              <td class="task-msg">{{ t.message || '-' }}</td>
              <td style="color: var(--color-text-muted); font-size: 0.75rem; white-space: nowrap;">{{ t.created_at }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="!tasks.length" class="empty-state">
        <div class="empty-icon">📋</div>
        <p class="empty-text">暂无任务</p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { tasksApi } from '@/api/modules'

const tasks = ref<any[]>([])

onMounted(async () => {
  const res = await tasksApi.list({ page_size: 100 })
  tasks.value = res.data.data?.items || []
})

function taskStatusClass(status: string) {
  switch (status) {
    case 'pending': return 'badge-warning'
    case 'running': return 'badge-info'
    case 'success': return 'badge-success'
    case 'failed': case 'timeout': return 'badge-danger'
    default: return 'badge-neutral'
  }
}

function statusLabel(s: string) {
  const map: Record<string, string> = {
    pending: '等待',
    running: '执行中',
    success: '成功',
    failed: '失败',
    timeout: '超时',
    cancelled: '取消',
  }
  return map[s] || s
}

function typeClass(type: string) {
  if (type.includes('forward')) return 'type-forward'
  if (type.includes('latency')) return 'type-latency'
  if (type.includes('check')) return 'type-check'
  if (type.includes('system')) return 'type-system'
  return 'type-other'
}

function typeLabel(type: string) {
  const map: Record<string, string> = {
    'start_forward_rule': '启动转发',
    'stop_forward_rule': '停止转发',
    'restart_forward_rule': '重启转发',
    'create_forward_rule': '创建转发',
    'delete_forward_rule': '删除转发',
    'latency_test': '延迟测试',
    'batch_latency_test': '批量延迟',
    'check_listen_port': '检测监听',
    'check_target_reachable': '检测目标',
    'check_forward_chain': '检测链路',
    'get_system_info': '系统信息',
    'reload_nftables': '重载nft',
    'check_gost_version': 'gost版本',
  }
  return map[type] || type
}
</script>

<style scoped>
.table-wrap { overflow-x: auto; }

.task-type {
  font-size: 0.7rem;
  font-weight: 600;
  padding: 0.125rem 0.5rem;
  border-radius: 6px;
  white-space: nowrap;
}
.type-forward { background: #dbeafe; color: #1d4ed8; }
.type-latency { background: #fef3c7; color: #b45309; }
.type-check { background: #ede9fe; color: #6d28d9; }
.type-system { background: #e0e7ff; color: #4338ca; }
.type-other { background: #f1f5f9; color: #475569; }

.task-msg {
  font-size: 0.75rem;
  color: var(--color-text-secondary);
  max-width: 280px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.empty-state {
  text-align: center;
  padding: 3rem 1rem;
}
.empty-icon { font-size: 2.5rem; margin-bottom: 0.5rem; }
.empty-text { color: var(--color-text-muted); font-size: 0.875rem; margin: 0; }
</style>
