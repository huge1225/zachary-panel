<template>
  <n-config-provider :theme="darkTheme">
    <n-message-provider>
      <n-layout has-sider style="height: 100vh">
        <n-layout-sider bordered :width="220" :collapsed-width="64" collapse-mode="width" show-trigger>
          <div class="logo">
            <h2>⚡ Zachary Panel</h2>
          </div>
          <n-menu :options="menuOptions" :value="currentRoute" @update:value="navigate" />
        </n-layout-sider>
        <n-layout>
          <n-layout-header bordered style="padding: 12px 24px; display: flex; justify-content: space-between; align-items: center;">
            <n-breadcrumb>
              <n-breadcrumb-item>{{ currentPageTitle }}</n-breadcrumb-item>
            </n-breadcrumb>
            <n-space>
              <n-tag :type="systemOnline ? 'success' : 'error'" size="small">
                {{ systemOnline ? '● 系统正常' : '● 系统异常' }}
              </n-tag>
            </n-space>
          </n-layout-header>
          <n-layout-content style="padding: 24px;">
            <Dashboard v-if="currentRoute === 'dashboard'" />
            <AgentList v-else-if="currentRoute === 'agents'" @select-agent="handleSelectAgent" />
            <ForwardRules v-else-if="currentRoute === 'rules'" :preselected-agent="selectedAgentId" />
          </n-layout-content>
        </n-layout>
      </n-layout>
    </n-message-provider>
  </n-config-provider>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { darkTheme, NConfigProvider, NLayout, NLayoutSider, NLayoutHeader, NLayoutContent, NMenu, NBreadcrumb, NBreadcrumbItem, NTag, NSpace, NMessageProvider } from 'naive-ui'
import Dashboard from './views/Dashboard.vue'
import AgentList from './views/AgentList.vue'
import ForwardRules from './views/ForwardRules.vue'
import api from './api/index.js'

const currentRoute = ref('dashboard')
const selectedAgentId = ref('')
const systemOnline = ref(true)

const currentPageTitle = computed(() => {
  const map = { dashboard: '仪表盘', agents: '节点管理', rules: '转发规则' }
  return map[currentRoute.value] || ''
})

const menuOptions = [
  { label: '仪表盘', key: 'dashboard', icon: () => '📊' },
  { label: '节点管理', key: 'agents', icon: () => '🖥' },
  { label: '转发规则', key: 'rules', icon: () => '🔀' },
]

function navigate(key) {
  currentRoute.value = key
}

function handleSelectAgent(agentId) {
  selectedAgentId.value = agentId
  currentRoute.value = 'rules'
}

// 定期检查系统状态
onMounted(async () => {
  try {
    await api.get('/dashboard', { timeout: 5000 })
    systemOnline.value = true
  } catch {
    systemOnline.value = false
  }
  setInterval(async () => {
    try {
      await api.get('/dashboard', { timeout: 5000 })
      systemOnline.value = true
    } catch {
      systemOnline.value = false
    }
  }, 30000)
})
</script>

<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
.logo { padding: 20px 16px; text-align: center; }
.logo h2 { color: #63e2b7; font-size: 18px; }
</style>
