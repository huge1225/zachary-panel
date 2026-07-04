<template>
  <div class="card form-card">
    <div class="form-header">
      <h2 class="page-title">{{ isEdit ? '编辑规则' : '创建转发规则' }}</h2>
      <p class="form-subtitle">配置端口转发规则，支持 nftables 和 gost 两种模式</p>
    </div>

    <form @submit.prevent="save" class="rule-form">
      <!-- Section: Basic -->
      <div class="form-section">
        <div class="form-section-title">基本信息</div>
        <div class="form-grid">
          <div class="form-field col-span-2">
            <label class="form-label">规则名称 <span class="required">*</span></label>
            <input v-model="form.name" class="input" placeholder="例如：web-forward-8080" required />
          </div>

          <div class="form-field">
            <label class="form-label">目标节点 <span class="required">*</span></label>
            <select v-model="form.node_id" class="select" required :class="{ 'select-error': errorNodeId }">
              <option value="" disabled>请选择节点...</option>
              <option v-for="n in nodes" :key="n.node_id" :value="n.node_id">
                {{ n.name }} ({{ n.public_ip || n.last_ip || n.node_id }})
              </option>
            </select>
            <p v-if="errorNodeId" class="field-error">请选择一个节点</p>
            <p v-else-if="!nodes.length" class="field-hint">⚠️ 没有可用节点，请先添加节点</p>
          </div>

          <div class="form-field">
            <label class="form-label">备注</label>
            <input v-model="form.remark" class="input" placeholder="可选" />
          </div>
        </div>
      </div>

      <!-- Section: Forwarding -->
      <div class="form-section">
        <div class="form-section-title">转发配置</div>
        <div class="form-grid">
          <div class="form-field">
            <label class="form-label">模式</label>
            <select v-model="form.mode" class="select">
              <option value="nft">nftables (内核级)</option>
              <option value="gost">gost (应用层)</option>
            </select>
          </div>

          <div class="form-field">
            <label class="form-label">协议</label>
            <select v-model="form.protocol" class="select">
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="tcp_udp">TCP + UDP</option>
            </select>
          </div>

          <div class="form-field">
            <label class="form-label">监听端口 <span class="required">*</span></label>
            <input v-model="form.listen_port" type="number" class="input" placeholder="例如：8080" required min="1" max="65535" />
          </div>

          <div class="form-field">
            <label class="form-label">隧道类型</label>
            <select v-model="form.tunnel_type" class="select">
              <option value="plain">Plain (直连)</option>
              <option value="ws">WebSocket</option>
              <option value="wss">WebSocket Secure</option>
            </select>
          </div>

          <div class="form-field">
            <label class="form-label">目标地址 <span class="required">*</span></label>
            <input v-model="form.target_addr" class="input" placeholder="例如：10.0.0.5" required />
          </div>

          <div class="form-field">
            <label class="form-label">目标端口 <span class="required">*</span></label>
            <input v-model="form.target_port" type="number" class="input" placeholder="例如：80" required min="1" max="65535" />
          </div>
        </div>
      </div>

      <!-- Actions -->
      <div class="form-actions">
        <router-link to="/rules" class="btn btn-secondary">取消</router-link>
        <button type="submit" class="btn btn-primary" :disabled="saving">
          {{ saving ? '保存中...' : (isEdit ? '保存修改' : '创建规则') }}
        </button>
      </div>
    </form>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { rulesApi, nodesApi } from '@/api/modules'

const route = useRoute()
const router = useRouter()
const isEdit = !!route.params.id

const nodes = ref<any[]>([])
const saving = ref(false)
const errorNodeId = ref(false)

const form = reactive({
  name: '', mode: 'nft', protocol: 'tcp',
  listen_port: '', target_addr: '', target_port: '',
  node_id: '', tunnel_type: 'plain', remark: '',
})

onMounted(async () => {
  // Load nodes for dropdown
  try {
    const res = await nodesApi.list({ page_size: 200 })
    nodes.value = res.data.data?.items || []
  } catch { /* empty */ }

  if (isEdit) {
    const res = await rulesApi.get(Number(route.params.id))
    const d = res.data.data
    Object.assign(form, {
      name: d.name, mode: d.mode, protocol: d.protocol,
      listen_port: d.listen_port, target_addr: d.target_addr, target_port: d.target_port,
      node_id: d.node_id, tunnel_type: d.tunnel_type || 'plain', remark: d.remark || '',
    })
  }
})

async function save() {
  errorNodeId.value = !form.node_id
  if (errorNodeId.value) return

  saving.value = true
  try {
    if (isEdit) {
      await rulesApi.update(Number(route.params.id), form)
    } else {
      await rulesApi.create(form)
    }
    router.push('/rules')
  } catch (e: any) {
    alert(e.message || '操作失败')
  } finally {
    saving.value = false
  }
}
</script>

<style scoped>
.form-card {
  max-width: 720px;
  padding: 1.75rem;
}

.form-header { margin-bottom: 1.5rem; }
.form-subtitle {
  font-size: 0.8125rem;
  color: var(--color-text-muted);
  margin-top: 0.25rem;
}

.form-section {
  margin-bottom: 1.5rem;
  padding-bottom: 1.5rem;
  border-bottom: 1px solid #f1f5f9;
}
.form-section:last-of-type { border-bottom: none; margin-bottom: 1rem; }
.form-section-title {
  font-size: 0.8125rem;
  font-weight: 600;
  color: var(--color-text-secondary);
  margin-bottom: 1rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}
.col-span-2 { grid-column: span 2; }

.form-field {
  display: flex;
  flex-direction: column;
}
.required { color: #ef4444; }

.select-error { border-color: #ef4444; }
.field-error { font-size: 0.75rem; color: #ef4444; margin-top: 0.25rem; }
.field-hint { font-size: 0.75rem; color: var(--color-warning); margin-top: 0.25rem; }

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.625rem;
  padding-top: 0.5rem;
}
</style>
