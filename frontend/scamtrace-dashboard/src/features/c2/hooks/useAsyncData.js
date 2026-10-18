import { useCallback, useEffect, useEffectEvent, useState } from 'react'

/**
 * Load data for `key` with `loader(signal)`; reloads when the key changes or reload() is called.
 * Returns { data, error, loading, reload }. The previous data stays visible while reloading.
 */
export function useAsyncData(loader, key) {
  const [state, setState] = useState({ key: null, data: null, error: null })
  const [nonce, setNonce] = useState(0)
  const requestKey = `${key}#${nonce}`
  const load = useEffectEvent((signal) => loader(signal))

  useEffect(() => {
    const controller = new AbortController()
    let active = true
    Promise.resolve(load(controller.signal)).then(
      (data) => active && setState({ key: requestKey, data, error: null }),
      (error) => active && setState((previous) => ({ key: requestKey, data: previous.data, error })),
    )
    return () => {
      active = false
      controller.abort()
    }
  }, [requestKey])

  const reload = useCallback(() => setNonce((value) => value + 1), [])
  const loading = state.key !== requestKey
  return { data: state.data, error: loading ? null : state.error, loading, reload }
}
