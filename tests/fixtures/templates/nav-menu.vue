<template>
  <nav class="nav" v-cloak>
    <ul>
      <li v-for="item in items" :key="item.id">
        <component :is="item.href ? 'a' : 'span'" v-bind:[attrName]="item.href" v-once>
          {{ item.label }}
        </component>
      </li>
    </ul>

    <p v-pre>{{ this is not rendered }} <b>also raw</b></p>

    <time :datetime="publishedAt">{{ formattedDate }}</time>
  </nav>
</template>

<script setup>
import { ref } from 'vue';

const items = ref([]);
const attrName = 'href';
</script>
