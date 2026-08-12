<template>
  <Teleport to="body" :disabled="!teleportEnabled">
    <Transition name="modal" @before-enter="onEnter" @after-leave="onLeave">
      <div v-if="open" class="modal-backdrop" @click.self="close" @keydown.esc="close">
        <div class="modal" role="dialog" aria-modal="true" :aria-labelledby="titleId">
          <header class="modal__header">
            <slot name="title">Modal</slot>
            <button type="button" class="modal__close" aria-label="Close" @click="close">&times;</button>
          </header>

          <div class="modal__body">
            <slot>Body</slot>
          </div>

          <footer class="modal__footer">
            <slot name="footer" :ok="confirm">
              <button type="button" @click="confirm">OK</button>
            </slot>
          </footer>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup>
import { ref } from 'vue';

const open = ref(false);
const teleportEnabled = ref(true);
</script>
