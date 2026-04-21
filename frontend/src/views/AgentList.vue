<template>
  <div class="agent-list">
    <n-card>
      <template #header>
        <div class="card-header">
          <h3>🖥️ 节点管理</h3>
          <n-space>
            <n-button type="primary" @click="showAddModal = true">
              <template #icon>
                <n-icon><add-circle-outline /></n-icon>
              </template>
              添加节点
            </n-button>
            <n-button @click="refreshAgents">
              <template #icon>
                <n-icon><refresh-outline /></n-icon>
              </template>
              刷新
            </n-button>
          </n-space>
        </div>
      </template>

      <n-data-table
        :columns="columns"
        :data="agents"
        :loading="loading"
        :pagination="pagination"
        :row-class-name="getRowClassName"
      />

      <!-- 添加节点模态框 -->
      <n-modal v-model:show="showAddModal" preset="dialog" title="添加节点">
        <template #header>
          <div class="modal-header">
            <h4>添加新节点</h4>
          </div>
        </template>
        
        <div class="form-content">
          <n-form
            ref="formRef"
            :model="formValue"
            :rules="rules"
            label-placement="left"
            label-width="auto"
            require-mark-placement="right-hanging"
            size="medium"
          >
            <n-form-item label="节点ID" path="id">
              <n-input v-model:value="formValue.id" placeholder="请输入节点ID" />
            </n-form-item>
            
            <n-form-item label="节点名称" path="hostname">
              <n-input v-model:value="formValue.hostname" placeholder="请输入节点名称" />
            </n-form-item>
            
            <n-form-item label="IP地址" path="ip">
              <n-input v-model:value="formValue.ip" placeholder="请输入IP地址" />
            </n-form-item>
            
            <n-form-item label="Token" path="token">
              <n-input v-model:value="formValue.token" type="password" placeholder="请输入Token" show-password-on="mousedown" />
            </n-form-item>
            
            <n-form-item label="操作系统" path="os">
              <n-select v-model:value="formValue.os" :options="osOptions" />
            </n-form-item>
            
            <n-form-item label="架构" path="arch">
              <n-select v-model:value="formValue.arch" :options="archOptions" />
            </n-form-item>
          </n-form>
        </div>
        
        <template #action>
          <n-space>
            <n-button @click="showAddModal = false">取消</n-button>
            <n-button type="primary" :loading="submitting" @click="handleAddAgent">添加</n-button>
          </n-space>
        </template>
      </n-modal>
    </n-card>
  </div>
</template>

<script setup>
import { ref, onMounted, h } from 'vue'
import { NTag, NButton, NSpace, useMessage } from 'naive-ui'
import { AddCircleOutline, RefreshOutline } from '@vicons/ionicons5'
import api from '../api'

const message = useMessage()
const loading = ref(false)
const submitting = ref(false)
const showAddModal = ref(false)
const agents = ref([])
const formRef = ref(null)

const formValue = ref({
  id: '',
  hostname: '',
  ip: '',
  token: '',
  os: 'linux',
  arch: 'amd64'
})

const rules = {
  id: {
    required: true,
    message: '请输入节点ID',
    trigger: 'blur'
  },
  hostname: {
    required: true,
    message: '请输入节点名称',
    trigger: 'blur'
  },
  ip: {
    required: true,
    message: '请输入IP地址',
    trigger: 'blur'
  },
  token: {
    required: true,
    message: '请输入Token',
    trigger: 'blur'
  }
}

const osOptions = [
  { label: 'Linux', value: 'linux' },
  { label: 'Windows', value: 'windows' },
  { label: 'macOS', value: 'darwin' }
]

const archOptions = [
  { label: 'amd64', value: 'amd64' },
  { label: 'arm64', value: 'arm64' },
  { label: '386', value: '386' }
]

const pagination = {
  pageSize: 10
}

const columns = [
  {
    title: '节点ID',
    key: 'id',
    width: 150
  },
  {
    title: '节点名称',
    key: 'hostname',
    width: 180
  },
  {
    title: 'IP地址',
    key: 'ip',
    width: 150
  },
  {
    title: '操作系统',
    key: 'os',
    width: 120
  },
  {
    title: '架构',
    key: 'arch',
    width: 100
  },
  {
    title: '状态',
    key: 'status',
    width: 100,
    render: (row) => {
      return h(NTag, {
        type: row.status === 'online' ? 'success' : 'error',
        size: 'small'
      }, { default: () => row.status === 'online' ? '在线' : '离线' })
    }
  },
  {
    title: '最后活跃',
    key: 'last_seen',
    width: 180,
    render: (row) => {
      return row.last_seen && row.last_seen !== '0001-01-01T00:00:00Z' ? new Date(row.last_seen).toLocaleString() : '从未'
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
            type: 'primary',
            onClick: () => viewAgentRules(row.id)
          }, { default: () => '规则' }),
          h(NButton, {
            size: 'small',
            type: 'error',
            onClick: () => handleDeleteAgent(row.id)
          }, { default: () => '删除' })
        ]
      })
    }
  }
]

const loadAgents = async () => {
  loading.value = true
  try {
    const response = await api.get('/agents')
    agents.value = response.data.agents || []
  } catch (error) {
    console.error('Failed to load agents:', error)
    message.error('加载节点列表失败')
  } finally {
    loading.value = false
  }
}

const refreshAgents = () => {
  loadAgents()
  message.success('已刷新节点列表')
}

const handleAddAgent = async () => {
  try {
    await formRef.value?.validate()
    submitting.value = true
    
    await api.post('/agents', formValue.value)
    
    message.success('节点添加成功')
    showAddModal.value = false
    formRef.value?.restoreValidation()
    loadAgents()
  } catch (error) {
    console.error('Failed to add agent:', error)
    message.error('添加节点失败')
  } finally {
    submitting.value = false
  }
}

const handleDeleteAgent = async (agentId) => {
  try {
    await api.delete(`/agents/${agentId}`)
    message.success('节点删除成功')
    loadAgents()
  } catch (error) {
    console.error('Failed to delete agent:', error)
    message.error('删除节点失败')
  }
}

const viewAgentRules = (agentId) => {
  // 导航到规则页面，并选中该节点
  emit('select-agent', agentId)
}

const getRowClassName = (row) => {
  return row.status === 'online' ? 'online-row' : 'offline-row'
}

onMounted(() => {
  loadAgents()
})

const emit = defineEmits(['select-agent'])
</script>

<style scoped>
.agent-list {
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

.online-row {
  background-color: rgba(24, 160, 88, 0.06);
}

.offline-row {
  background-color: rgba(208, 48, 80, 0.06);
}
</style>