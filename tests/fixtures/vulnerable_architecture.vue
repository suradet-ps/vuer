<template>
  <div>
    <p>{{ greeting }}</p>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'

const props = defineProps({ name: String })

props.name = 'renamed'

const count = ref(0)
const doubled = computed(() => {
  count++
  return count * 2
})
</script>
