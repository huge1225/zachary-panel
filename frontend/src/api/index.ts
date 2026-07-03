import axios from 'axios'
import { useAuthStore } from '@/stores/auth'
import router from '@/router'

const api = axios.create({
  baseURL: '/api',
  timeout: 15000,
})

// Request interceptor — attach JWT
api.interceptors.request.use((config) => {
  const auth = useAuthStore()
  if (auth.token) {
    config.headers.Authorization = `Bearer ${auth.token}`
  }
  return config
})

// Response interceptor — handle 401
api.interceptors.response.use(
  (res) => {
    const data = res.data as ApiResponse<any>
    if (data.code !== 0 && data.code !== undefined) {
      return Promise.reject(new Error(data.message || 'Request failed'))
    }
    return res
  },
  (err) => {
    if (err.response?.status === 401) {
      const auth = useAuthStore()
      auth.logout()
      router.push('/login')
    }
    return Promise.reject(err)
  },
)

export default api

interface ApiResponse<T> {
  code: number
  message: string
  data: T
}
