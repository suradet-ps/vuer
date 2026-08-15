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
import { useRoute } from 'vue-router'

const route = useRoute()

const userInput = ref(localStorage.getItem('u') ?? '')
const redirect = ref(route.query.next)
const userAvatar = ref(route.query.avatar)
const items = ref([1, 2, 3])
const input = route.query.q
const next = route.query.next
const jwt = route.query.token

el.innerHTML = userInput
document.write('<h1>x</h1>')
eval(input)
location.href = next
localStorage.setItem('auth_token', jwt)
iframe.contentWindow.postMessage({ type: 'ping' }, '*')
window.open(redirect, '_blank')
fetch('/api/users')
</script>
