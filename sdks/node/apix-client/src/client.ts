import axios, { AxiosInstance } from 'axios';

export class APIxError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'APIxError';
  }
}

export interface ClientOptions {
  apiKey?: string;
  bearerToken?: string;
  baseUrl?: string;
}

export class APIxClient {
  private client: AxiosInstance;

  constructor(options: ClientOptions = {}) {
    const baseUrl = options.baseUrl || 'http://localhost:8000';
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (options.apiKey) {
      headers['x-api-key'] = options.apiKey;
    }
    if (options.bearerToken) {
      headers['Authorization'] = `Bearer ${options.bearerToken}`;
    }

    this.client = axios.create({
      baseURL: baseUrl,
      headers,
      timeout: 60000,
    });
  }

  async getHealth(): Promise<any> {
    try {
      const res = await this.client.get('/api/health');
      return res.data;
    } catch (error: any) {
      this.handleError(error);
    }
  }

  async getDailyIndex(limit: number = 30): Promise<any[]> {
    try {
      const res = await this.client.get('/api/v1/index/daily', { params: { limit } });
      return res.data;
    } catch (error: any) {
      this.handleError(error);
    }
  }

  async getRouteIndex(routeId: string, limit: number = 30): Promise<any[]> {
    try {
      const res = await this.client.get(`/api/v1/index/route/${routeId.toUpperCase()}`, { params: { limit } });
      return res.data;
    } catch (error: any) {
      this.handleError(error);
    }
  }

  async getMaterialityGap(): Promise<any> {
    try {
      const res = await this.client.get('/api/v1/index/materiality');
      return res.data;
    } catch (error: any) {
      this.handleError(error);
    }
  }

  async getDashboardStats(): Promise<any> {
    try {
      const res = await this.client.get('/api/v1/dashboard/stats');
      return res.data;
    } catch (error: any) {
      this.handleError(error);
    }
  }

  async surveyRoute(routeId: string = 'DEL-BOM', advanceDays: number = 7, forceLive: boolean = false): Promise<any[]> {
    try {
      const res = await this.client.post('/api/v1/scraper/survey-instant', null, {
        params: { route: routeId.toUpperCase(), advance_days: advanceDays, force_live: forceLive }
      });
      return res.data;
    } catch (error: any) {
      this.handleError(error);
    }
  }

  async listRoutes(): Promise<any[]> {
    try {
      const res = await this.client.get('/api/v1/routes');
      return res.data;
    } catch (error: any) {
      this.handleError(error);
    }
  }

  async fetch(url: string, options: any = {}): Promise<any> {
    try {
      const response = await this.client.post('/fetch', { url, ...options });
      return response.data;
    } catch (error: any) {
      this.handleError(error);
    }
  }

  private handleError(error: any): never {
    if (error.response) {
      const detail = error.response.data?.detail || error.response.data;
      throw new APIxError(`HTTP ${error.response.status}: ${JSON.stringify(detail)}`);
    }
    throw new APIxError(error.message);
  }
}
