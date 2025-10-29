export interface GenericApiResponse {
  /** Timestamp of response generation */
  timestamp: string;

  /** Same code as returned in the HTTP response. Repeated here for logging/debugging purposes */
  status: string;

  /** Same code as returned in the HTTP response. Repeated here for logging/debugging purposes */
  statusCode: number;

  /** Error class type */
  type?: string;

  /** Specific error message */
  message?: string;

  /** The requested path causing the response */
  path?: string;

  /** Name of the service that returned the response */
  artifact: string;

  /** Version of the service - for debugging purposes */
  version: string;
}

export interface GenericSuccessResponse<T = any> {
  /** Timestamp of response generation */
  timestamp: string;

  /** Same code as returned in the HTTP response */
  status: string;

  /** Same code as returned in the HTTP response */
  statusCode: number;

  /** The actual response data */
  data: T;

  /** Name of the service that returned the response */
  artifact: string;

  /** Version of the service - for debugging purposes */
  version: string;
}
