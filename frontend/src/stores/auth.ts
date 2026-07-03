import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { authApi } from '@/api/modules'

export const useAuthStore = defineStore('auth', () => {
  const token = ref(localStorage.getItem('zp_token') || '')
  const username = ref(localStorage.getItem('zp_username') || '')

  const isAuthenticated = computed(() => !!token.value)

  async function login(user: string, password: string) {
    const res = await authApi.login(user, password)
    const data = res.data.data
    token.value = data.token
    username.value = data.username || user
    localStorage.setItem('zp_token', data.token)
    localStorage.setItem('zp_username', data.username || user)
  }

  function logout() {
    token.value = ''
    username.value = ''
    localStorage.removeItem('zp_token')
    localStorage.removeItem('zp_username')
  }

  return { token, username, isAuthenticated, login, logout }
})
