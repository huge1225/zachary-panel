<template>
  <div class="login-page">
    <div class="login-card">
      <div class="login-header">
        <div class="login-logo">🚀</div>
        <h1 class="login-title">Zachary Panel</h1>
        <p class="login-subtitle">转发管理控制台</p>
      </div>
      <form @submit.prevent="handleLogin" class="login-form">
        <div class="form-group">
          <label class="form-label">用户名</label>
          <input
            v-model="form.username"
            type="text"
            class="input"
            placeholder="admin"
            required
            autocomplete="username"
          />
        </div>
        <div class="form-group">
          <label class="form-label">密码</label>
          <input
            v-model="form.password"
            type="password"
            class="input"
            placeholder="••••••••"
            required
            autocomplete="current-password"
          />
        </div>
        <p v-if="error" class="login-error">{{ error }}</p>
        <button
          type="submit"
          :disabled="loading"
          class="login-btn"
        >
          <span v-if="loading" class="spinner"></span>
          {{ loading ? '登录中...' : '登 录' }}
        </button>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const auth = useAuthStore()

const form = reactive({ username: '', password: '' })
const error = ref('')
const loading = ref(false)

async function handleLogin() {
  error.value = ''
  loading.value = true
  try {
    await auth.login(form.username, form.password)
    router.push('/')
  } catch (e: any) {
    error.value = e.response?.data?.message || e.message || '登录失败'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #312e81 100%);
}

.login-card {
  background: white;
  border-radius: 16px;
  box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
  padding: 2.5rem;
  width: 100%;
  max-width: 380px;
  margin: 1rem;
}

.login-header {
  text-align: center;
  margin-bottom: 2rem;
}
.login-logo {
  font-size: 2.5rem;
  margin-bottom: 0.5rem;
}
.login-title {
  font-size: 1.5rem;
  font-weight: 700;
  color: #0f172a;
  margin: 0;
}
.login-subtitle {
  font-size: 0.8125rem;
  color: #64748b;
  margin-top: 0.25rem;
}

.login-form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
.form-group {
  display: flex;
  flex-direction: column;
}

.login-error {
  font-size: 0.8125rem;
  color: #ef4444;
  margin: 0;
  padding: 0.5rem 0.75rem;
  background: #fef2f2;
  border-radius: 6px;
  border: 1px solid #fecaca;
}

.login-btn {
  width: 100%;
  background: linear-gradient(135deg, #3b82f6, #2563eb);
  color: white;
  font-size: 0.875rem;
  font-weight: 600;
  border: none;
  border-radius: 8px;
  padding: 0.625rem;
  cursor: pointer;
  transition: all 0.15s;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
}
.login-btn:hover:not(:disabled) {
  box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
  transform: translateY(-1px);
}
.login-btn:disabled { opacity: 0.6; cursor: not-allowed; }

.spinner {
  width: 14px;
  height: 14px;
  border: 2px solid rgba(255,255,255,0.3);
  border-top-color: white;
  border-radius: 50%;
  animation: spin 0.6s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
</style>
