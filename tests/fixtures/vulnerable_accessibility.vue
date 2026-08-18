<template>
  <div>
    <img src="logo.png">
    <div @click="open()">Open</div>
    <input type="text" v-model="name">
    <button @click="save()">Save</button>
  </div>
</template>

<script setup>
import { ref } from 'vue'

const name = ref('')

function open() {}
function save() {}
</script>
