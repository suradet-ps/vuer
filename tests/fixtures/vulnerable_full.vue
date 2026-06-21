<template>
  <div v-html="userInput">x</div>
  <a :href="redirect">click</a>
  <iframe src="https://example.com"></iframe>
  <img :src="userAvatar">
  <ul>
    <li v-for="item in items">{{ item }}</li>
  </ul>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const userInput = ref('<b>x</b>')
const redirect = ref('/home')
const userAvatar = ref('/avatar.png')
const items = ref([1, 2, 3])

watch(userInput, (n) => { console.log(n) })

el.innerHTML = userInput
document.write('<h1>x</h1>')
eval(input)
location.href = next
localStorage.setItem('auth_token', jwt)
iframe.contentWindow.postMessage({ type: 'ping' }, '*')
window.open('https://example.com', '_blank')
fetch('/api/users')
</script>
