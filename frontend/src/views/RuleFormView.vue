<template>
  <div class="bg-white rounded-lg p-5 shadow-sm max-w-2xl">
    <h2 class="text-lg font-semibold mb-4">{{ isEdit ? '编辑规则' : '创建规则' }}</h2>
    <form @submit.prevent="save" class="space-y-3">
      <div class="grid grid-cols-2 gap-3">
        <input v-model="form.name" placeholder="规则名称 *" required class="col-span-2 border rounded px-3 py-2 text-sm" />
        <select v-model="form.mode" class="border rounded px-3 py-2 text-sm">
          <option value="nft">nftables</option>
          <option value="gost">gost</option>
        </select>
        <select v-model="form.protocol" class="border rounded px-3 py-2 text-sm">
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
          <option value="tcp_udp">TCP+UDP</option>
        </select>
        <input v-model="form.listen_port" type="number" placeholder="监听端口 *" required class="border rounded px-3 py-2 text-sm" />
        <input v-model="form.target_addr" placeholder="目标地址 *" required class="border rounded px-3 py-2 text-sm" />
        <input v-model="form.target_port" type="number" placeholder="目标端口 *" required class="border rounded px-3 py-2 text-sm" />
        <select v-model="form.tunnel_type" class="border rounded px-3 py-2 text-sm">
          <option value="plain">Plain</option>
          <option value="ws">WebSocket</option>
          <option value="wss">WebSocket Secure</option>
        </select>
        <input v-model="form.node_id" placeholder="节点 ID *" required class="col-span-2 border rounded px-3 py-2 text-sm" />
        <input v-model="form.remark" placeholder="备注" class="col-span-2 border rounded px-3 py-2 text-sm" />
      </div>
      <div class="flex justify-end gap-2 pt-2">
        <router-link to="/rules" class="px-4 py-2 text-sm rounded border">取消</router-link>
        <button type="submit" class="px-4 py-2 text-sm rounded bg-blue-600 text-white">{{ isEdit ? '保存' : '创建' }}</button>
      </div>
    </form>
  </div>
</template>

<script setup lang="ts">
import { reactive, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { rulesApi } from '@/api/modules'

const route = useRoute()
const router = useRouter()
const isEdit = !!route.params.id

const form = reactive({
  name: '', mode: 'nft', protocol: 'tcp',
  listen_port: '', target_addr: '', target_port: '',
  node_id: '', tunnel_type: 'plain', remark: '',
})

onMounted(async () => {
  if (isEdit) {
    const res = await rulesApi.get(Number(route.params.id))
    const d = res.data.data
    Object.assign(form, {
      name: d.name, mode: d.mode, protocol: d.protocol,
      listen_port: d.listen_port, target_addr: d.target_addr, target_port: d.target_port,
      node_id: d.node_id, tunnel_type: d.tunnel_type || 'plain', remark: d.remark || '',
    })
  }
})

async function save() {
  if (isEdit) {
    await rulesApi.update(Number(route.params.id), form)
  } else {
    await rulesApi.create(form)
  }
  router.push('/rules')
}
</script>
