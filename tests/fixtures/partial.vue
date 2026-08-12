<template>
  <div>
    <div v-html="trustedContent">Trusted</div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const trustedContent = ref('<span>Safe</span>')
</script>
