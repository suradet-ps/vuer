<template>
  <div v-html="raw">flagged, no comment</div>
  <!-- vuer-ignore[no-v-html] -->
  <div v-html="trusted">silenced by previous-line comment</div>
</template>

<script setup lang="ts">
const raw = localStorage.getItem('raw')
const trusted = localStorage.getItem('trusted')

el.innerHTML = raw  // will be flagged (no ignore)
el.innerHTML = trusted  // vuer-ignore[no-inner-html]
</script>
