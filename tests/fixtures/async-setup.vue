<template>
  <div>
    <p>Loading user…</p>
  </div>
</template>

<script>
export default {
  async setup() {
    await new Promise((resolve) => setTimeout(resolve, 100))
    return { data: 'loaded' }
  },
}
</script>
