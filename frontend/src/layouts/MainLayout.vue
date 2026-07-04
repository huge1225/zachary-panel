<template>
  <div class="layout">
    <!-- Sidebar -->
    <aside class="sidebar" :class="{ collapsed: sidebarCollapsed }">
      <div class="sidebar-header">
        <span class="sidebar-logo">🚀</span>
        <span v-if="!sidebarCollapsed" class="sidebar-brand">Zachary Panel</span>
      </div>
      <nav class="sidebar-nav">
        <router-link
          v-for="item in menu"
          :key="item.path"
          :to="item.path"
          class="nav-item"
          :class="{ active: isActive(item.path) }"
          :title="item.label"
        >
          <span class="nav-icon">{{ item.icon }}</span>
          <span v-if="!sidebarCollapsed" class="nav-label">{{ item.label }}</span>
        </router-link>
      </nav>
      <div class="sidebar-footer">
        <button class="nav-item collapse-btn" @click="sidebarCollapsed = !sidebarCollapsed">
          <span class="nav-icon">{{ sidebarCollapsed ? '▶' : '◀' }}</span>
          <span v-if="!sidebarCollapsed" class="nav-label">收起</span>
        </button>
        <button class="nav-item logout-btn" @click="logout">
          <span class="nav-icon">🚪</span>
          <span v-if="!sidebarCollapsed" class="nav-label">退出登录</span>
        </button>
      </div>
    </aside>

    <!-- Main content area -->
    <div class="main-area">
      <header class="topbar">
        <div class="topbar-left">
          <h1 class="topbar-title">{{ currentTitle }}</h1>
        </div>
        <div class="topbar-right">
          <div class="user-chip">
            <div class="user-avatar">{{ (auth.username || '?')[0].toUpperCase() }}</div>
            <span class="user-name">{{ auth.username }}</span>
          </div>
        </div>
      </header>
      <main class="content">
        <router-view v-slot="{ Component }">
          <transition name="fade" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const sidebarCollapsed = ref(false)

const menu = [
  { path: '/', label: '仪表盘', icon: '📊' },
  { path: '/nodes', label: '节点管理', icon: '🖥️' },
  { path: '/rules', label: '转发规则', icon: '🔀' },
  { path: '/tasks', label: '任务列表', icon: '📋' },
  { path: '/latency', label: '延迟测试', icon: '⏱️' },
  { path: '/security', label: '安全事件', icon: '🛡️' },
  { path: '/settings', label: '系统设置', icon: '⚙️' },
]

const currentTitle = computed(() => {
  const item = menu.find(m => m.path === route.path || (m.path !== '/' && route.path.startsWith(m.path)))
  return item?.label || '仪表盘'
})

function isActive(path: string) {
  if (path === '/') return route.path === '/'
  return route.path.startsWith(path)
}

function logout() {
  auth.logout()
  router.push('/login')
}
</script>

<style scoped>
.layout {
  display: flex;
  height: 100vh;
  overflow: hidden;
}

/* ── Sidebar ── */
.sidebar {
  width: 230px;
  background: #0f172a;
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
  transition: width 0.2s ease;
}
.sidebar.collapsed {
  width: 60px;
}

.sidebar-header {
  height: 56px;
  display: flex;
  align-items: center;
  gap: 0.625rem;
  padding: 0 1rem;
  border-bottom: 1px solid rgba(255,255,255,0.06);
  flex-shrink: 0;
}
.sidebar-logo { font-size: 1.25rem; }
.sidebar-brand {
  font-size: 0.9375rem;
  font-weight: 700;
  color: #f8fafc;
  letter-spacing: -0.01em;
}

.sidebar-nav {
  flex: 1;
  padding: 0.625rem 0.5rem;
  display: flex;
  flex-direction: column;
  gap: 2px;
  overflow-y: auto;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.5rem 0.625rem;
  border-radius: 8px;
  font-size: 0.8125rem;
  color: #94a3b8;
  text-decoration: none;
  transition: all 0.12s ease;
  cursor: pointer;
  background: none;
  border: none;
  width: 100%;
  text-align: left;
}
.nav-item:hover {
  background: rgba(255,255,255,0.06);
  color: #e2e8f0;
}
.nav-item.active {
  background: #2563eb;
  color: white;
  font-weight: 500;
}
.nav-icon {
  font-size: 1rem;
  width: 20px;
  text-align: center;
  flex-shrink: 0;
}
.nav-label {
  white-space: nowrap;
  overflow: hidden;
}

.sidebar-footer {
  padding: 0.5rem;
  border-top: 1px solid rgba(255,255,255,0.06);
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.collapse-btn { font-size: 0.75rem; }
.logout-btn:hover { background: rgba(239, 68, 68, 0.15); color: #fca5a5; }

/* ── Main area ── */
.main-area {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.topbar {
  height: 56px;
  background: white;
  border-bottom: 1px solid #e2e8f0;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 1.5rem;
  flex-shrink: 0;
}
.topbar-title {
  font-size: 1rem;
  font-weight: 600;
  color: #1e293b;
}

.user-chip {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.user-avatar {
  width: 28px;
  height: 28px;
  border-radius: 50%;
  background: linear-gradient(135deg, #3b82f6, #6366f1);
  color: white;
  font-size: 0.75rem;
  font-weight: 600;
  display: flex;
  align-items: center;
  justify-content: center;
}
.user-name { font-size: 0.8125rem; color: #64748b; font-weight: 500; }

.content {
  flex: 1;
  overflow-y: auto;
  padding: 1.5rem;
}
</style>
