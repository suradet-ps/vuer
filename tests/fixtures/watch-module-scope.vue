<script>
import { ref } from 'vue'

const count = ref(0)

// Module scope: this watcher is created once when the module loads and
// has no component lifecycle to dispose it.
watch(count, (newVal) => {
  console.log('Count changed:', newVal)
})
</script>
