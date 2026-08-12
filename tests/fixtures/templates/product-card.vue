<template>
  <article class="product-card" :class="{ featured }">
    <img :src="product.thumbnail" :alt="product.title" loading="lazy" />
    <h3>{{ product.title }}</h3>
    <p v-text="product.excerpt"></p>

    <div class="price-row">
      <span class="price">{{ currency(product.price) }}</span>
      <span v-if="product.discount" class="badge">-{{ product.discount }}%</span>
    </div>

    <slot name="actions" :item="product">
      <button type="button" @click="addToCart(product)">Add to cart</button>
    </slot>

    <span v-show="product.stock === 0" class="out-of-stock">Out of stock</span>
  </article>
</template>

<script setup>
import { defineProps } from 'vue';

defineProps({
  product: { type: Object, required: true },
  featured: { type: Boolean, default: false },
});
</script>
