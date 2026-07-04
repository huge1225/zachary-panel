import api from './index'

export const authApi = {
  login(username: string, password: string) {
    return api.post('/auth/login', { username, password })
  },
  me() {
    return api.get('/auth/me')
  },
}

export const nodesApi = {
  list(params?: { page?: number; page_size?: number; status?: string; search?: string }) {
    return api.get('/nodes', { params })
  },
  get(id: number) {
    return api.get(`/nodes/${id}`)
  },
  create(data: { name: string; public_ip?: string; remark?: string }) {
    return api.post('/nodes', data)
  },
  update(id: number, data: any) {
    return api.put(`/nodes/${id}`, data)
  },
  delete(id: number) {
    return api.delete(`/nodes/${id}`)
  },
  installCommand(id: number, ttlMinutes?: number) {
    return api.get(`/nodes/${id}/install-command`, { params: { ttl_minutes: ttlMinutes || 30 } })
  },
}

export const rulesApi = {
  list(params?: { page?: number; page_size?: number; node_id?: string; status?: string }) {
    return api.get('/rules', { params })
  },
  get(id: number) {
    return api.get(`/rules/${id}`)
  },
  create(data: any) {
    return api.post('/rules', data)
  },
  update(id: number, data: any) {
    return api.put(`/rules/${id}`, data)
  },
  delete(id: number) {
    return api.delete(`/rules/${id}`)
  },
  start(id: number) {
    return api.post(`/rules/${id}/start`)
  },
  stop(id: number) {
    return api.post(`/rules/${id}/stop`)
  },
  restart(id: number) {
    return api.post(`/rules/${id}/restart`)
  },
}

export const tasksApi = {
  list(params?: { page?: number; page_size?: number; node_id?: string; status?: string }) {
    return api.get('/tasks', { params })
  },
  get(id: number) {
    return api.get(`/tasks/${id}`)
  },
}

export const dashboardApi = {
  get() {
    return api.get('/dashboard')
  },
}

export const latencyApi = {
  test(data: any) {
    return api.post('/latency-tests', data)
  },
  list(params?: { page?: number; page_size?: number }) {
    return api.get('/latency-tests', { params })
  },
}

export const securityApi = {
  list(params?: { page?: number; page_size?: number; severity?: string }) {
    return api.get('/security-events', { params })
  },
}
