<template>
  <form class="login-form" @submit.prevent="handleSubmit" novalidate>
    <h1>{{ title }}</h1>

    <p v-if="error" class="error" role="alert">{{ error }}</p>

    <label for="email">Email</label>
    <input
      id="email"
      v-model.trim="email"
      type="email"
      name="email"
      autocomplete="email"
      required
    >

    <label for="password">Password</label>
    <input id="password" v-model="password" type="password" autocomplete="current-password" required />

    <div class="actions">
      <button type="submit" :disabled="loading">
        <span v-if="loading" class="spinner" aria-hidden="true"></span>
        {{ loading ? 'Signing in…' : 'Sign in' }}
      </button>
      <button type="button" @click="resetForm">Reset</button>
    </div>

    <p class="hint">{{ t('login.hint') }} <a :href="helpUrl" target="_blank" rel="noopener">Help</a></p>
  </form>
</template>

<script setup>
import { ref } from 'vue';

const title = 'Sign in to your account';
const email = ref('');
const password = ref('');
const loading = ref(false);
const error = ref('');
const helpUrl = '/help';
</script>

<style scoped>
.login-form {
  max-width: 360px;
  margin: 0 auto;
}
</style>
