<template>
  <div>
    <div class="page-header">
      <h2 class="page-title">延迟测试</h2>
    </div>

    <!-- Test configuration -->
    <div class="card config-card">
      <div class="config-tabs">
        <button class="tab-btn" :class="{ active: activeTab === 'custom' }" @click="activeTab = 'custom'">自定义目标</button>
        <button class="tab-btn" :class="{ active: activeTab === 'rule' }" @click="activeTab = 'rule'">规则链路测试</button>
        <button class="tab-btn" :class="{ active: activeTab === 'multi' }" @click="activeTab = 'multi'">多节点对比</button>
      </div>

      <!-- Custom target -->
      <div v-if="activeTab === 'custom'" class="config-body">
        <div class="config-grid">
          <div class="config-field">
            <label class="form-label">目标节点</label>
            <select v-model="customTest.node_id" class="select">
              <option value="">选择节点...</option>
              <option v-for="n in nodes" :key="n.node_id" :value="n.node_id">{{ n.name }}</option>
            </select>
          </div>
          <div class="config-field">
            <label class="form-label">测试类型</label>
            <select v-model="customTest.test_type" class="select">
              <option value="tcp">TCP</option>
              <option value="http">HTTP</option>
              <option value="icmp">ICMP</option>
              <option value="dns">DNS</option>
            </select>
          </div>
          <div class="config-field">
            <label class="form-label">目标地址 <span class="req">*</span></label>
            <input v-model="customTest.target_addr" class="input" placeholder="例如：8.8.8.8" />
          </div>
          <div class="config-field">
            <label class="form-label">目标端口</label>
            <input v-model.number="customTest.target_port" type="number" class="input" placeholder="80" />
          </div>
        </div>
        <div class="config-actions">
          <button @click="runCustom" class="btn btn-primary" :disabled="!customTest.node_id || !customTest.target_addr || testing">
            {{ testing ? '⏳ 测试中...' : '⚡ 开始测试' }}
          </button>
        </div>
      </div>

      <!-- Rule chain test -->
      <div v-if="activeTab === 'rule'" class="config-body">
        <div class="config-grid">
          <div class="config-field col-2">
            <label class="form-label">选择转发规则</label>
            <select v-model="ruleTestId" class="select" @change="onRuleSelect">
              <option value="">选择规则...</option>
              <option v-for="r in rules" :key="r.id" :value="r.id">
                {{ r.name }} — :{{ r.listen_port }} → {{ r.target_addr }}:{{ r.target_port }} ({{ r.node_name || r.node_id }})
              </option>
            </select>
          </div>
        </div>
        <div v-if="selectedRule" class="rule-chain-info">
          <div class="chain-step">
            <span class="chain-label">监听</span>
            <span class="chain-value">{{ selectedRule.listen_addr || '0.0.0.0' }}:{{ selectedRule.listen_port }}</span>
          </div>
          <div class="chain-arrow">→</div>
          <div class="chain-step">
            <span class="chain-label">转发</span>
            <span class="chain-value">{{ selectedRule.target_addr }}:{{ selectedRule.target_port }}</span>
          </div>
          <div class="chain-arrow">→</div>
          <div class="chain-step">
            <span class="chain-label">节点</span>
            <span class="chain-value">{{ selectedRule.node_name || selectedRule.node_id }}</span>
          </div>
        </div>
        <div class="config-actions">
          <button @click="testRuleChain" class="btn btn-primary" :disabled="!ruleTestId || testing">
            {{ testing ? '⏳ 测试中...' : '🔌 测试转发链路' }}
          </button>
          <button @click="testRuleListen" class="btn btn-secondary" :disabled="!ruleTestId || testing">检测监听端口</button>
          <button @click="testRuleTarget" class="btn btn-secondary" :disabled="!ruleTestId || testing">检测目标可达</button>
        </div>
      </div>

      <!-- Multi-node comparison -->
      <div v-if="activeTab === 'multi'" class="config-body">
        <div class="config-grid">
          <div class="config-field">
            <label class="form-label">测试类型</label>
            <select v-model="multiTest.test_type" class="select">
              <option value="tcp">TCP</option>
              <option value="http">HTTP</option>
              <option value="icmp">ICMP</option>
            </select>
          </div>
          <div class="config-field">
            <label class="form-label">目标地址 <span class="req">*</span></label>
            <input v-model="multiTest.target_addr" class="input" placeholder="例如：1.1.1.1" />
          </div>
          <div class="config-field">
            <label class="form-label">目标端口</label>
            <input v-model.number="multiTest.target_port" type="number" class="input" placeholder="443" />
          </div>
        </div>
        <div class="node-select-grid">
          <label v-for="n in nodes" :key="n.node_id" class="node-check" :class="{ checked: multiTest.node_ids.includes(n.node_id) }">
            <input type="checkbox" :value="n.node_id" v-model="multiTest.node_ids" />
            <span class="status-dot" :class="n.status === 'online' ? 'dot-green' : 'dot-gray'"></span>
            <span class="node-check-name">{{ n.name }}</span>
            <span class="node-check-ip">{{ n.public_ip || n.last_ip || '-' }}</span>
          </label>
        </div>
        <div class="config-actions">
          <button @click="runMulti" class="btn btn-primary" :disabled="multiTest.node_ids.length < 1 || !multiTest.target_addr || testing">
            {{ testing ? '⏳ 测试中...' : `📊 批量测试 (${multiTest.node_ids.length}个节点)` }}
          </button>
        </div>
      </div>
    </div>

    <!-- Results -->
    <div class="card results-card">
      <div class="results-header">
        <h3 class="results-title">测试结果</h3>
        <button v-if="results.length" @click="results = []" class="btn btn-ghost">清空</button>
      </div>

      <div v-if="!results.length" class="empty-state">
        <div class="empty-icon">⏱️</div>
        <p class="empty-text">暂无测试结果</p>
      </div>

      <div v-else class="results-table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>目标</th>
              <th>节点</th>
              <th>类型</th>
              <th>平均延迟</th>
              <th>最小</th>
              <th>最大</th>
              <th>丢包率</th>
              <th>状态</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(r, i) in results" :key="i">
              <td class="mono">{{ r.target_addr }}{{ r.target_port ? ':' + r.target_port : '' }}</td>
              <td>{{ r.node_name || r.node_id || '-' }}</td>
              <td><span class="badge badge-neutral" style="text-transform: uppercase;">{{ r.test_type }}</span></td>
              <td class="latency-value" :class="latencyClass(r.avg_latency_ms)">{{ fmtLatency(r.avg_latency_ms) }}</td>
              <td class="mono">{{ fmtLatency(r.min_latency_ms) }}</td>
              <td class="mono">{{ fmtLatency(r.max_latency_ms) }}</td>
              <td :class="lossClass(r.loss_rate)">{{ (r.loss_rate * 100).toFixed(1) }}%</td>
              <td><span class="badge" :class="r.status === 'success' ? 'badge-success' : 'badge-danger'">{{ r.status }}</span></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Toast -->
    <transition name="fade">
      <div v-if="toast" class="toast" :class="toastType" @click="toast = ''">{{ toast }}</div>
    </transition>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, computed } from 'vue'
import { latencyApi, nodesApi, rulesApi } from '@/api/modules'

const activeTab = ref('custom')
const testing = ref(false)
const nodes = ref<any[]>([])
const rules = ref<any[]>([])
const results = ref<any[]>([])
const toast = ref('')
const toastType = ref('toast-success')
const ruleTestId = ref('')
const selectedRule = computed(() => rules.value.find(r => r.id === Number(ruleTestId.value)))

const customTest = reactive({ node_id: '', test_type: 'tcp', target_addr: '', target_port: 80 })
const multiTest = reactive({ test_type: 'tcp', target_addr: '', target_port: 443, node_ids: [] as string[] })

onMounted(async () => {
  try {
    const [nodesRes, rulesRes] = await Promise.all([
      nodesApi.list({ page_size: 200 }),
      rulesApi.list({ page_size: 200 }),
    ])
    nodes.value = nodesRes.data.data?.items || []
    rules.value = rulesRes.data.data?.items || []
  } catch { /* empty */ }
})

function showToast(msg: string, type = 'toast-success') {
  toast.value = msg
  toastType.value = type
  setTimeout(() => toast.value = '', 4000)
}

async function runCustom() {
  testing.value = true
  try {
    await latencyApi.single({
      node_id: customTest.node_id,
      test_type: customTest.test_type,
      target_addr: customTest.target_addr,
      target_port: customTest.target_port,
      count: 5,
    })
    showToast('✅ 测试任务已下发，等待结果...')
    // Poll for results
    setTimeout(() => loadResults(customTest.target_addr), 3000)
  } catch (e: any) {
    showToast(`❌ ${e.message || '测试失败'}`, 'toast-error')
  }
  testing.value = false
}

function onRuleSelect() {
  // Just update the computed
}

async function testRuleChain() {
  if (!ruleTestId.value) return
  testing.value = true
  try {
    const res = await rulesApi.testChain(Number(ruleTestId.value))
    showToast(`🔌 链路测试已创建: ${res.data.data?.task_id || ''}`)
  } catch (e: any) {
    showToast(`❌ ${e.message || '测试失败'}`, 'toast-error')
  }
  testing.value = false
}

async function testRuleListen() {
  if (!ruleTestId.value) return
  testing.value = true
  try {
    const res = await rulesApi.testListen(Number(ruleTestId.value))
    showToast(`✅ 监听端口检测已创建: ${res.data.data?.task_id || ''}`)
  } catch (e: any) {
    showToast(`❌ ${e.message || '测试失败'}`, 'toast-error')
  }
  testing.value = false
}

async function testRuleTarget() {
  if (!ruleTestId.value) return
  testing.value = true
  try {
    const res = await rulesApi.testTarget(Number(ruleTestId.value))
    showToast(`✅ 目标可达检测已创建: ${res.data.data?.task_id || ''}`)
  } catch (e: any) {
    showToast(`❌ ${e.message || '测试失败'}`, 'toast-error')
  }
  testing.value = false
}

async function runMulti() {
  if (multiTest.node_ids.length === 0) return
  testing.value = true
  try {
    const res = await latencyApi.batch({
      node_ids: multiTest.node_ids,
      test_type: multiTest.test_type,
      target_addr: multiTest.target_addr,
      target_port: multiTest.target_port,
      count: 5,
    })
    showToast(`📊 批量测试已下发 (${res.data.data?.count || 0}个节点)`)
    setTimeout(() => loadResults(multiTest.target_addr), 5000)
  } catch (e: any) {
    showToast(`❌ ${e.message || '测试失败'}`, 'toast-error')
  }
  testing.value = false
}

async function loadResults(targetAddr?: string) {
  try {
    const res = await latencyApi.list({ page_size: 20 })
    const items = res.data.data?.items || []
    if (targetAddr) {
      const filtered = items.filter((r: any) => r.target_addr?.includes(targetAddr))
      if (filtered.length) results.value = filtered
    } else {
      results.value = items
    }
  } catch { /* empty */ }
}

function fmtLatency(ms: number | null | undefined) {
  if (ms == null) return '-'
  return ms.toFixed(1) + 'ms'
}

function latencyClass(ms: number | null | undefined) {
  if (ms == null) return ''
  if (ms < 50) return 'lat-good'
  if (ms < 150) return 'lat-ok'
  return 'lat-bad'
}

function lossClass(rate: number) {
  if (rate === 0) return 'loss-zero'
  if (rate < 0.1) return 'lat-ok'
  return 'lat-bad'
}

onMounted(() => loadResults())
</script>

<style scoped>
.config-card { padding: 0; margin-bottom: 1rem; overflow: hidden; }

.config-tabs {
  display: flex;
  border-bottom: 1px solid var(--color-border);
  background: #f8fafc;
}
.tab-btn {
  padding: 0.75rem 1.25rem;
  font-size: 0.8125rem;
  font-weight: 500;
  color: var(--color-text-secondary);
  background: none;
  border: none;
  cursor: pointer;
  transition: all 0.12s;
  border-bottom: 2px solid transparent;
}
.tab-btn:hover { color: var(--color-text-primary); background: rgba(0,0,0,0.02); }
.tab-btn.active {
  color: var(--color-primary);
  border-bottom-color: var(--color-primary);
  background: white;
}

.config-body { padding: 1.25rem; }

.config-grid {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr 1fr;
  gap: 1rem;
  margin-bottom: 1rem;
}
.col-2 { grid-column: span 2; }

.config-field {
  display: flex;
  flex-direction: column;
}
.req { color: #ef4444; }

.config-actions {
  display: flex;
  gap: 0.5rem;
}

/* Rule chain info */
.rule-chain-info {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 1rem;
  background: #f8fafc;
  border-radius: 10px;
  margin-bottom: 1rem;
  flex-wrap: wrap;
}
.chain-step { display: flex; flex-direction: column; gap: 2px; }
.chain-label { font-size: 0.7rem; color: var(--color-text-muted); text-transform: uppercase; font-weight: 600; }
.chain-value { font-size: 0.8125rem; font-weight: 500; font-family: 'SF Mono', monospace; }
.chain-arrow { color: var(--color-primary); font-size: 1.25rem; font-weight: 700; }

/* Node checkboxes */
.node-select-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 0.5rem;
  margin-bottom: 1rem;
}
.node-check {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--color-border);
  border-radius: 8px;
  cursor: pointer;
  font-size: 0.8125rem;
  transition: all 0.12s;
}
.node-check:hover { background: #f8fafc; }
.node-check.checked {
  border-color: var(--color-primary);
  background: #eff6ff;
}
.node-check input { display: none; }
.node-check-name { font-weight: 500; flex: 1; }
.node-check-ip { font-size: 0.7rem; color: var(--color-text-muted); font-family: monospace; }

/* Results */
.results-card { padding: 1.25rem; }
.results-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}
.results-title { font-size: 0.875rem; font-weight: 600; margin: 0; }

.results-table-wrap { overflow-x: auto; }
.mono { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.75rem; }

.latency-value { font-weight: 600; font-variant-numeric: tabular-nums; }
.lat-good { color: #16a34a; }
.lat-ok { color: #ca8a04; }
.lat-bad { color: #dc2626; }
.loss-zero { color: #16a34a; font-weight: 500; }

.empty-state {
  text-align: center;
  padding: 2.5rem 1rem;
}
.empty-icon { font-size: 2.5rem; margin-bottom: 0.5rem; }
.empty-text { color: var(--color-text-muted); font-size: 0.875rem; margin: 0; }

/* Toast */
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
}
.toast-success { background: #dcfce7; color: #15803d; border: 1px solid #bbf7d0; }
.toast-error { background: #fee2e2; color: #b91c1c; border: 1px solid #fecaca; }

@media (max-width: 768px) {
  .config-grid { grid-template-columns: 1fr 1fr; }
}
</style>
