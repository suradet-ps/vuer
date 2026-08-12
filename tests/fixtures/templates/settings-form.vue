<template>
  <form @submit.prevent="save">
    <fieldset>
      <legend>Notifications</legend>
      <label>
        <input type="checkbox" v-model="prefs.email" /> Email
      </label>
      <label>
        <input type="checkbox" v-model="prefs.sms" /> SMS
      </label>
    </fieldset>

    <fieldset>
      <legend>Region</legend>
      <select v-model.number="region">
        <option v-for="r in regions" :key="r.code" :value="r.code">{{ r.name }}</option>
      </select>
    </fieldset>

    <div class="themes">
      <label v-for="t in themes" :key="t" :class="{ selected: theme === t }">
        <input type="radio" :value="t" v-model="theme" /> {{ t }}
      </label>
    </div>

    <input type="range" v-model.number="volume" min="0" max="100" step="1" />

    <textarea v-model.lazy="notes" rows="4"></textarea>

    <button type="submit">Save</button>
  </form>
</template>

<script setup>
import { reactive, ref } from 'vue';

const prefs = reactive({ email: true, sms: false });
const region = ref('us');
const theme = ref('light');
const volume = ref(50);
const notes = ref('');
</script>
