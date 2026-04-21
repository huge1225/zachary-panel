<template>
  <div class="forward-rules">
    <n-card>
      <template #header>
        <div class="card-header">
          <h3>🔀 转发规则</h3>
          <n-space>
            <n-button type="primary" @click="showAddModal = true" :disabled="!selectedAgent">
              <template #icon>
                <n-icon><add-circle-outline /></n-icon>
              </template>
              添加规则
            </n-button>
            <n-button @click="refreshRules" :disabled="!selectedAgent">
              <template #icon>
                <n-icon><refresh-outline /></n-icon>
              </template>
              刷新
            </n-button>
            <n-select v-model:value="selectedAgent" :options="agentOptions" placeholder="选择节点" style="width: 200px" />
          </n-space>
        </div>
      </template>

      <!-- 节点选择提示 -->
      <n-alert v-if="!selectedAgent" type="warning" style="margin-bottom: 20px;">
        请先选择一个节点来管理转发规则
      </n-alert>

      <!-- 规则列表 -->
      <n-data-table
        v-if="selectedAgent"
        :columns="columns"
        :data="ruleList"
        :loading="loading"
        :pagination="pagination"
        :row-class-name="getRowClassName"
      />

      <!-- 添加规则模态框 -->
      <n-modal v-model:show="showAddModal" preset="dialog" title="添加转发规则">
        <template #header>
          <div class="modal-header">
            <h4>添加转发规则</h4>
          </div>
        </template>
        
        <div class="form-content">
          <n-form
            ref="formRef"
            :model="formValue"
            :rules="formRules"
            label-placement="left"
            label-width="auto"
            require-mark-placement="right-hanging"
            size="medium"
          >
            <n-form-item label="监听地址" path="listen_addr">
              <n-input v-model:value="formValue.listen_addr" placeholder="例如: 0.0.0.0:8080" />
            </n-form-item>
            
            <n-form-item label="目标地址" path="target_addr">
              <n-input v-model:value="formValue.target_addr" placeholder="例如: example.com:80" />
            </n-form-item>
            
            <n-form-item label="协议" path="protocol">
              <n-select v-model:value="formValue.protocol" :options="protocolOptions" />
            </n-form-item>
            
            <n-form-item label="启用状态" path="enabled">
              <n-switch v-model:value="formValue.enabled" />
            </n-form-item>
            
            <n-form-item label="额外配置" path="extra">
              <n-input v-model:value="formValue.extra" type="textarea" placeholder="JSON格式的额外配置" />
            </n-form-item>
          </n-form>
        </div>
        
        <template #action>
          <n-space>
            <n-button @click="showAddModal = false">取消</n-button>
            <n-button type="primary" :loading="submitting" @click="handleAddRule">添加</n-button>
          </n-space>
        </template>
      </n-modal>
    </n-card>
  </div>
</template>

<script setup>
import { ref, onMounted, computed, watch, h } from 'vue'
import { NTag, NButton, NSpace, useMessage } from 'naive-ui'
import { AddCircleOutline, RefreshOutline } from '@vicons/ionicons5'
import api from '../api'

const props = defineProps({
  preselectedAgent: {
    type: String,
    default: ''
  }
})

const message = useMessage()
const loading = ref(false)
const submitting = ref(false)
const showAddModal = ref(false)
const selectedAgent = ref(props.preselectedAgent || '')
const ruleList = ref([])
const agents = ref([])
const formRef = ref(null)

const formValue = ref({
  listen_addr: '',
  target_addr: '',
  protocol: 'tcp',
  enabled: true,
  extra: '{}'
})

const formRules = {
  listen_addr: {
    required: true,
    message: '请输入监听地址',
    trigger: 'blur'
  },
  target_addr: {
    required: true,
    message: '请输入目标地址',
    trigger: 'blur'
  },
  protocol: {
    required: true,
    message: '请选择协议',
    trigger: 'blur'
  }
}

const protocolOptions = [
  { label: 'TCP', value: 'tcp' },
  { label: 'UDP', value: 'udp' },
  { label: 'HTTP', value: 'http' },
  { label: 'HTTPS', value: 'https' },
  { label: 'WS', value: 'ws' },
  { label: 'WSS', value: 'wss' }
]

const pagination = {
  pageSize: 10
}

const columns = [
  {
    title: '监听地址',
    key: 'listen_addr',
    width: 150
  },
  {
    title: '目标地址',
    key: 'target_addr',
    width: 150
  },
  {
    title: '协议',
    key: 'protocol',
    width: 100
  },
  {
    title: '状态',
    key: 'enabled',
    width: 100,
    render: (row) => {
      return h(NTag, {
        type: row.enabled ? 'success' : 'error',
        size: 'small'
      }, { default: () => row.enabled ? '启用' : '禁用' })
    }
  },
  {
    title: '创建时间',
    key: 'created_at',
    width: 180,
    render: (row) => {
      return row.created_at ? new Date(row.created_at).toLocaleString() : '-'
    }
  },
  {
    title: '操作',
    key: 'actions',
    width: 200,
    render: (row) => {
      return h(NSpace, { size: 'small' }, {
        default: () => [
          h(NButton, {
            size: 'small',
            type: row.enabled ? 'warning' : 'success',
            onClick: () => toggleRule(row.id, row.enabled)
          }, { default: () => row.enabled ? '禁用' : '启用' }),
          h(NButton, {
            size: 'small',
            type: 'error',
            onClick: () => deleteRule(row.id)
          }, { default: () => '删除' })
        ]
      })
    }
  }
]

const agentOptions = computed(() => {
  return agents.value.map(agent => ({
    label: `${agent.hostname || agent.id} (${agent.ip})`,
    value: agent.id
  }))
})

const loadAgents = async () => {
  try {
    const response = await api.get('/agents')
    agents.value = response.data.agents || []
  } catch (error) {
    console.error('Failed to load agents:', error)
  }
}

const loadRules = async () => {
  if (!selectedAgent.value) return
  
  loading.value = true
  try {
    const response = await api.get(`/agents/${selectedAgent.value}/rules`)
    ruleList.value = response.data.rules || []
  } catch (error) {
    console.error('Failed to load rules:', error)
    message.error('加载规则列表失败')
  } finally {
    loading.value = false
  }
}

const refreshRules = () => {
  loadRules()
  message.success('已刷新规则列表')
}

const handleAddRule = async () => {
  try {
    await formRef.value?.validate()
    submitting.value = true
    
    await api.post(`/agents/${selectedAgent.value}/rules`, formValue.value)
    
    message.success('规则添加成功')
    showAddModal.value = false
    formRef.value?.restoreValidation()
    // 重置表单
    formValue.value = {
      listen_addr: '',
      target_addr: '',
      protocol: 'tcp',
      enabled: true,
      extra: '{}'
    }
    loadRules()
  } catch (error) {
    console.error('Failed to add rule:', error)
    message.error('添加规则失败')
  } finally {
    submitting.value = false
  }
}

const toggleRule = async (ruleId, currentEnabled) => {
  try {
    await api.put(`/rules/${ruleId}`, {
      enabled: !currentEnabled
    })
    message.success(`规则已${!currentEnabled ? '启用' : '禁用'}`)
    loadRules()
  } catch (error) {
    console.error('Failed to toggle rule:', error)
    message.error('操作失败')
  }
}

const deleteRule = async (ruleId) => {
  try {
    await api.delete(`/rules/${ruleId}`)
    message.success('规则删除成功')
    loadRules()
  } catch (error) {
    console.error('Failed to delete rule:', error)
    message.error('删除规则失败')
  }
}

const getRowClassName = (row) => {
  return row.enabled ? 'enabled-row' : 'disabled-row'
}

onMounted(() => {
  loadAgents()
})

// 监听选中节点变化
watch(selectedAgent, (val) => {
  if (val) {
    loadRules()
  }
})
</script>

<style scoped>
.forward-rules {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.modal-header {
  display: flex;
  align-items: center;
}

.form-content {
  margin: 20px 0;
}

.enabled-row {
  background-color: rgba(24, 160, 88, 0.06);
}

.disabled-row {
  background-color: rgba(208, 48, 80, 0.06);
}
</style>
