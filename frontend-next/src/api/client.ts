const TOKEN_KEY = 'link2nas_token'

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number = 0,
    public readonly data: unknown = null,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

export async function request<T = unknown>(path: string, options: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem(TOKEN_KEY)
  const isFormData = options.body instanceof FormData

  const response = await fetch(path, {
    ...options,
    headers: {
      ...(!isFormData ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { 'X-Api-Key': token } : {}),
      ...(options.headers as Record<string, string> | undefined ?? {}),
    },
  })

  if (response.status === 204) return null as T

  const contentType = response.headers.get('content-type') ?? ''
  const text = await response.text()

  let data: unknown = null
  if (text) {
    if (contentType.includes('application/json')) {
      try { data = JSON.parse(text) } catch { data = { message: text } }
    } else {
      data = { message: text }
    }
  }

  if (!response.ok) {
    console.warn('[API ERROR DEBUG]', {
      path,
      status: response.status,
      contentType,
      text,
      data,
    })

    // If the stored token is rejected as invalid, clear it and notify ProtectedRoute
    if (response.status === 401) {
      try {
        const stored = localStorage.getItem(TOKEN_KEY)
        if (stored) {
          localStorage.removeItem(TOKEN_KEY)
          window.dispatchEvent(new CustomEvent('auth-expired'))
        }
      } catch { /* ignore */ }
    }

    const d = data as Record<string, unknown> | null
    let message = (d?.error as string | undefined) ?? (d?.message as string | undefined) ?? `HTTP ${response.status}`
    if (typeof message === 'string' && message.trim().startsWith('<')) {
      message = `Server error HTTP ${response.status}`
    }
    throw new ApiError(message, response.status, data)
  }

  return data as T
}
