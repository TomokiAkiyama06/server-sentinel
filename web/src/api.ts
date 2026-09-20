export type ApiFailure = 'unauthorized' | 'unavailable' | 'invalid_response' | 'invalid_request' | 'cancelled';

/** Fixed local messages only: no response body, credentials, URL or cause retained. */
export class ApiError extends Error {
  constructor(readonly code: ApiFailure) {
    super(code);
    this.name = 'ApiError';
  }
}

export function createApiClient(origin: string, request: typeof fetch = fetch) {
  const deployment = new URL(origin);
  if (!['http:', 'https:'].includes(deployment.protocol)) throw new ApiError('invalid_request');
  return {
    async read<T>(path: string, decode: (value: unknown) => T, signal?: AbortSignal): Promise<T> {
      let url: URL;
      try {
        if (!path.startsWith('/api/') || /[\\#]/.test(path)) throw new Error();
        url = new URL(path, deployment.origin);
        if (url.origin !== deployment.origin || !url.pathname.startsWith('/api/')) throw new Error();
      } catch { throw new ApiError('invalid_request'); }
      let response: Response;
      try {
        response = await request(url.href, {
          method: 'GET', credentials: 'same-origin', mode: 'same-origin',
          cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
          headers: { Accept: 'application/json' }, ...(signal ? { signal } : {}),
        });
      } catch { throw new ApiError(signal?.aborted ? 'cancelled' : 'unavailable'); }
      if (response.status === 401 || response.status === 403) throw new ApiError('unauthorized');
      if (!response.ok) throw new ApiError('unavailable');
      if (response.headers.get('Content-Type')?.split(';')[0]?.trim() !== 'application/json') {
        throw new ApiError('invalid_response');
      }
      try { return decode(await response.json()); }
      catch { throw new ApiError(signal?.aborted ? 'cancelled' : 'invalid_response'); }
    },
  };
}
