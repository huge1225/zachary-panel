import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'Login',
      component: () => import('@/views/LoginView.vue'),
      meta: { guest: true },
    },
    {
      path: '/',
      component: () => import('@/layouts/MainLayout.vue'),
      meta: { requiresAuth: true },
      children: [
        { path: '', name: 'Dashboard', component: () => import('@/views/DashboardView.vue') },
        { path: 'nodes', name: 'Nodes', component: () => import('@/views/NodesView.vue') },
        { path: 'nodes/:id', name: 'NodeDetail', component: () => import('@/views/NodeDetailView.vue') },
        { path: 'rules', name: 'Rules', component: () => import('@/views/RulesView.vue') },
        { path: 'rules/create', name: 'RuleCreate', component: () => import('@/views/RuleFormView.vue') },
        { path: 'rules/:id/edit', name: 'RuleEdit', component: () => import('@/views/RuleFormView.vue') },
        { path: 'tasks', name: 'Tasks', component: () => import('@/views/TasksView.vue') },
        { path: 'latency', name: 'Latency', component: () => import('@/views/LatencyView.vue') },
        { path: 'security', name: 'Security', component: () => import('@/views/SecurityView.vue') },
        { path: 'settings', name: 'Settings', component: () => import('@/views/SettingsView.vue') },
      ],
    },
  ],
})

router.beforeEach((to, _from, next) => {
  const auth = useAuthStore()
  if (to.meta.requiresAuth && !auth.isAuthenticated) {
    next('/login')
  } else if (to.meta.guest && auth.isAuthenticated) {
    next('/')
  } else {
    next()
  }
})

export default router
