export function isInvalidGrantError(err: unknown): boolean {
  if (!err) return false
  const e = err as { name?: string; message?: string; errorCode?: string; body?: string; status?: number }
  const msg = `${e.name ?? ''} ${e.errorCode ?? ''} ${e.message ?? ''} ${e.body ?? ''}`.toLowerCase()

  return (
    e.errorCode === 'invalid_grant' ||
    e.name === 'InvalidGrantError' ||
    msg.includes('invalid_grant') ||
    msg.includes("session doesn't have required client")
  )
}

export function isAuthFailureError(err: unknown): boolean {
  if (!err) return false
  const e = err as { message?: string; errorCode?: string; status?: number; name?: string; body?: string }
  const msg = `${e.name ?? ''} ${e.errorCode ?? ''} ${e.message ?? ''} ${e.body ?? ''}`.toLowerCase()

  return (
    e.status === 401 ||
    e.status === 403 ||
    isInvalidGrantError(err) ||
    msg.includes('unauthorized') ||
    msg.includes('authentication required') ||
    msg.includes('browser authorization timed out') ||
    msg.includes('authorization timed out') ||
    msg.includes('invalid_token')
  )
}
