<template>
  <div class="dashboard">
    <n-card>
      <template #header>
        <div class="card-header">
          <h3>📊 仪表盘</h3>
          <n-tag type="success" size="small">系统正常</n-tag>
        </div>
      </template>
      
      <div class="stats-grid">
        <n-statistic label="总节点数" :value="stats.totalAgents">
          <template #prefix>
            <n-icon><computer-outline /></n-icon>
          </template>
        </n-statistic>
        
        <n-statistic label="在线节点" :value="stats.onlineAgents">
          <template #prefix>
            <n-icon><checkmark-circle-outline /></n-icon>
          </template>
        </n-statistic>
        
        <n-statistic label="转发规则" :value="stats.totalRules">
          <template #prefix>
            <n-icon><router-outline /></n-icon>
          </template>
        </n-statistic>
        
        <n-statistic label="活跃规则" :value="stats.activeRules">
          <template #prefix>
            <n-icon><flash-outline /></n-icon>
          </template>
        </n-statistic>
      </div>

      <div class="recent-activity">
        <h4>📈 最近活动</h4>
        <n-timeline>
          <n-timeline-item v-for="activity in recentActivities" :key="activity.id" :type="activity.type">
            <template #header>
              <span class="activity-time">{{ activity.time }}</span>
            </template>
            <div class="activity-content">{{ activity.content }}</div>
          </n-timeline-item>
        </n-timeline>
      </div>
    </n-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useMessage } from 'naive-ui'
import { ComputerOutline, CheckmarkCircleOutline, RouterOutline, FlashOutline } from '@vicons/ionicons5'

const message = useMessage()

const stats = ref({
  totalAgents: 0,
  onlineAgents: 0,
  totalRules: 0,
  activeRules: 0
})

const recentActivities = ref([
  {
    id: 1,
    time: '2分钟前',
    type: 'success',
    content: '节点 node-1 上线'
  },
  {
    id: 2,
    time: '5分钟前',
    type: 'info',
    content: '新增转发规则: 8080 → target.com:80'
  },
  {
    id: 3,
    time: '10分钟前',
    type: 'warning',
    content: '节点 node-2 离线'
  }
])

const loadStats = async () => {
  try {
    const response = await fetch('/api/v1/dashboard')
    const data = await response.json()
    
    stats.value = {
      totalAgents: data.total_agents || 0,
      onlineAgents: data.online_agents || 0,
      totalRules: data.total_rules || 0,
      activeRules: data.active_rules || 0
    }
  } catch (error) {
    console.error('Failed to load stats:', error)
    message.error('加载统计数据失败')
  }
}

onMounted(() => {
  loadStats()
  // 定期刷新数据
  setInterval(loadStats, 30000)
})
</script>

<style scoped>
.dashboard {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 20px;
  margin-bottom: 30px;
}

.recent-activity {
  margin-top: 30px;
}

.recent-activity h4 {
  margin-bottom: 15px;
  color: #333;
}

.activity-time {
  font-size: 12px;
  color: #666;
}

.activity-content {
  color: #333;
  font-size: 14px;
}
</style>