<template>
  <div>
    <div v-html="userInput">Content</div>
    <img :src="imageUrl">
    <div style="color: red; font-size: 14px;">Styled</div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRoute } from 'vue-router'

const route = useRoute()

const userInput = ref(localStorage.getItem('userInput') ?? '')
const imageUrl = ref(route.query.img)

watch(count, (newVal) => {
  console.log('Count changed:', newVal)
})
</script>
