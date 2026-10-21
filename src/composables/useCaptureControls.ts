import { watch } from 'vue'
import { save } from '@tauri-apps/plugin-dialog'
import { useAppStore } from '@/stores/app'
import { useCaptureStore } from '@/stores/capture'
import { useTauri } from '@/composables/useTauri'
import { isCaptureFailure, type CaptureFailure } from '@/types/capture'
import { isMac, isWindows } from '@/ui/platform'

/** What to do about a failed start, by the backend's code. */
export function captureAdvice(failure: CaptureFailure): string {
  switch (failure.code) {
    case 'permission-denied':
      if (isMac) {
        return (
          'purdungeon cannot open /dev/bpf. Install ChmodBPF (it ships with Wireshark) ' +
          'or run purdungeon with sudo.'
        )
      }
      if (isWindows) {
        return (
          'Npcap refused the interface. Reinstall Npcap with "Restrict to administrators" ' +
          'unticked, or run purdungeon as administrator.'
        )
      }
      return (
        'Grant the binary capture rights with ' +
        'sudo setcap cap_net_raw,cap_net_admin=eip <path to purdungeon>, or run it as root.'
      )
    case 'driver-missing':
      return 'Install Npcap from npcap.com, then restart purdungeon.'
    case 'bad-filter':
      return 'The capture filter is not valid BPF. libpcap said: ' + failure.message
    case 'no-such-device':
      return 'That interface is gone. Pick another one.'
    case 'already-running':
      return 'A capture is already running. Stop it first.'
    default:
      return failure.message
  }
}

function asFailure(e: unknown): CaptureFailure {
  if (isCaptureFailure(e)) return e
  return { code: 'unknown', message: e instanceof Error ? e.message : String(e) }
}

/** Start, stop and save, with the stores kept honest about each. */
export function useCaptureControls() {
  const appStore = useAppStore()
  const captureStore = useCaptureStore()
  const { listInterfaces, startCapture, stopCapture, saveCapture } = useTauri()

  async function loadInterfaces() {
    try {
      captureStore.interfaces = await listInterfaces()
      captureStore.error = null
    } catch (e) {
      captureStore.interfaces = []
      captureStore.error = asFailure(e)
      return
    }
    if (
      captureStore.selectedInterface === null ||
      !captureStore.interfaces.some((i) => i.name === captureStore.selectedInterface)
    ) {
      // The first interface that is up and not the loopback, which is what a
      // span port is plugged into; the list is already in that order.
      const first =
        captureStore.interfaces.find((i) => i.is_up && !i.is_loopback) ?? captureStore.interfaces[0]
      captureStore.selectedInterface = first?.name ?? null
    }
  }

  // The list is fetched the first time the tab opens, not at startup: on a
  // machine without capture rights the error belongs on the capture tab.
  watch(
    () => appStore.activeView,
    (view) => {
      if (view === 'capture' && captureStore.interfaces.length === 0) void loadInterfaces()
    },
    { immediate: true },
  )

  async function start() {
    const iface = captureStore.selectedInterface
    if (!iface || captureStore.running || captureStore.starting) return
    captureStore.starting = true
    captureStore.error = null
    try {
      const status = await startCapture({
        interface: iface,
        filter: captureStore.filter.trim() || null,
        promiscuous: captureStore.promiscuous,
      })
      appStore.startLiveSession(status.interface)
      captureStore.selectedNo = null
      captureStore.follow = true
      captureStore.invalidatePages()
      captureStore.total = 0
      captureStore.firstNo = 1
      captureStore.applyStatus(status)
    } catch (e) {
      captureStore.error = asFailure(e)
    } finally {
      captureStore.starting = false
    }
  }

  async function stop() {
    if (!captureStore.running || captureStore.stopping) return
    captureStore.stopping = true
    try {
      captureStore.applyStatus(await stopCapture())
    } catch (e) {
      captureStore.error = asFailure(e)
    } finally {
      captureStore.stopping = false
    }
  }

  /** Pick a file and copy the capture there. Resolves to the bytes written,
   *  or null when the picker was dismissed. */
  async function saveAs(): Promise<{ path: string; bytes: number } | null> {
    const iface = captureStore.status?.interface ?? 'capture'
    const stamp = new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-')
    const path = await save({
      defaultPath: `purdungeon-${iface}-${stamp}.pcap`,
      filters: [{ name: 'Packet capture', extensions: ['pcap'] }],
    })
    if (!path) return null
    try {
      const bytes = await saveCapture(path)
      return { path, bytes }
    } catch (e) {
      captureStore.error = asFailure(e)
      return null
    }
  }

  return { loadInterfaces, start, stop, saveAs }
}
