<template>
  <div>
    <ul>
      <li v-for="user in users" v-if="user.active" :key="user.id">{{ user.name }}</li>
    </ul>
  </div>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'

const users = ref([])
const form = ref({ name: '' })

watch(form, (f) => console.log('form', f), { deep: true })

for (const u of users.value) {
  const r = reactive(u)
}

const doubled = computed(() => users.value.map((u) => ref(u)))
</script>
