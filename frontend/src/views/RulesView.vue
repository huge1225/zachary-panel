<template>
  <div>
    <div class="page-header">
      <h2 class="page-title">转发规则</h2>
      <router-link to="/rules/create" class="btn btn-primary">+ 创建规则</router-link>
    </div>

    <div class="card">
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>名称</th>
              <th>节点</th>
              <th>模式</th>
              <th>协议</th>
              <th>监听</th>
              <th>目标</th>
              <th>隧道</th>
              <th>状态</th>
              <th style="text-align: right;">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in rules" :key="r.id">
              <td style="font-weight: 600;">{{ r.name }}</td>
              <td>
                <div style="display: flex; flex-direction: column; gap: 2px;">
                  <span style="font-weight: 500;">{{ r.node_name || r.node_id }}</span>
                  <span style="font-size: 0.7rem; color: var(--color-text-muted); font-family: monospace;">{{ r.node_id }}</span>
                </div>
              </td>
              <td><span class="badge" :class="r.mode === 'gost' ? 'badge-purple' : 'badge-info'">{{ r.mode }}</span></td>
              <td><span class="badge badge-neutral" style="text-transform: uppercase;">{{ r.protocol }}</span></td>
              <td><span class="mono">:{{ r.listen_port }}</span></td>
              <td><span class="mono">{{ r.target_addr }}:{{ r.target_port }}</span></td>
              <td><span class="badge" :class="tunnelClass(r.tunnel_type)">{{ r.tunnel_type }}</span></td>
              <td><span class="badge" :class="ruleStatusClass(r.status)">{{ statusLabel(r.status) }}</span></td>
              <td style="text-align: right;">
                <div class="action-group">
                  <button v-if="r.status !== 'running'" @click="action(r.id, 'start')" class="action-btn action-start" title="启动">▶</button>
                  <button v-if="r.status === 'running'" @click="action(r.id, 'stop')" class="action-btn action-stop" title="停止">⏹</button>
                  <button @click="action(r.id, 'restart')" class="action-btn action-restart" title="重启">🔄</button>
                  <button @click="testChain(r.id)" class="action-btn action-test" title="测试链路">🔌</button>
                  <router-link :to="`/rules/${r.id}/edit`" class="action-btn action-edit" title="编辑">✏️</router-link>
                  <button @click="del(r.id)" class="action-btn action-delete" title="删除">🗑</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="!rules.length" class="empty-state">
        <div class="empty-icon">🔀</div>
        <p class="empty-text">还没有转发规则</p>
        <router-link to="/rules/create" class="btn btn-primary" style="margin-top: 0.75rem;">创建第一个规则</router-link>
      </div>
    </div>

    <!-- Test result toast -->
    <transition name="fade">
      <div v-if="testResult" class="toast" :class="testResultType" @click="testResult = ''">
        {{ testResult }}
      </div>
    </transition>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { rulesApi } from '@/api/modules'

const rules = ref<any[]>([])
const testResult = ref('')
const testResultType = ref('toast-success')

onMounted(load)

async function load() {
  const res = await rulesApi.list({ page_size: 100 })
  rules.value = res.data.data?.items || []
}

async function action(id: number, act: string) {
  try {
    await (rulesApi as any)[act](id)
    await load()
  } catch (e: any) {
    alert(e.message || '操作失败')
  }
}

async function testChain(id: number) {
  testResult.value = '测试中...'
  testResultType.value = 'toast-success'
  try {
    const res = await rulesApi.testChain(id)
    testResult.value = `✅ 链路测试任务已创建: ${res.data.data?.task_id || ''}`
    testResultType.value = 'toast-success'
  } catch (e: any) {
    testResult.value = `❌ 测试失败: ${e.message || ''}`
    testResultType.value = 'toast-error'
  }
  setTimeout(() => testResult.value = '', 4000)
}

async function del(id: number) {
  if (!confirm('确定删除此规则？')) return
  await rulesApi.delete(id)
  await load()
}

function ruleStatusClass(status: string) {
  switch (status) {
    case 'running': return 'badge-success'
    case 'stopped': return 'badge-neutral'
    case 'failed': return 'badge-danger'
    default: return 'badge-neutral'
  }
}

function statusLabel(status: string) {
  const map: Record<string, string> = {
    running: '运行中',
    stopped: '已停止',
    failed: '失败',
    pending: '等待中',
  }
  return map[status] || status
}

function tunnelClass(t: string) {
  switch (t) {
    case 'ws': return 'badge-info'
    case 'wss': return 'badge-success'
    default: return 'badge-neutral'
  }
}
</script>

<style scoped>
.mono { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.75rem; color: var(--color-text-secondary); }

.action-group {
  display: inline-flex;
  gap: 2px;
}
.action-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  border-radius: 6px;
  border: none;
  background: transparent;
  cursor: pointer;
  font-size: 0.8125rem;
  transition: all 0.12s;
  text-decoration: none;
}
.action-start:hover { background: #dcfce7; }
.action-stop:hover { background: #fef3c7; }
.action-restart:hover { background: #dbeafe; }
.action-test:hover { background: #ede9fe; }
.action-edit:hover { background: #e0e7ff; }
.action-delete:hover { background: #fee2e2; }

.empty-state {
  text-align: center;
  padding: 3rem 1rem;
}
.empty-icon { font-size: 2.5rem; margin-bottom: 0.5rem; }
.empty-text { color: var(--color-text-muted); font-size: 0.875rem; margin: 0; }

.table-wrap { overflow-x: auto; }

.toast {
  position: fixed;
  bottom: 1.5rem;
  right: 1.5rem;
  padding: 0.75rem 1.25rem;
  border-radius: 10px;
  font-size: 0.8125rem;
  font-weight: 500;
  box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1);
  cursor: pointer;
  z-index: 100;
  animation: slideUp 0.2s ease;
}
.toast-success { background: #dcfce7; color: #15803d; border: 1px solid #bbf7d0; }
.toast-error { background: #fee2e2; color: #b91c1c; border: 1px solid #fecaca; }

@keyframes slideUp {
  from { transform: translateY(10px); opacity: 0; }
  to { transform: translateY(0); opacity: 1; }
}
</style>
