# APIx Node.js / TypeScript Client

Official Node.js & TypeScript client for the **APIx Real-Time Airfare Price Index & Econometric Analytics Engine**.

## Installation

```bash
npm install apix-client
```

## Quickstart

```typescript
import { APIxClient } from 'apix-client';

const client = new APIxClient({
  baseUrl: 'http://localhost:8001',
});

async function main() {
  // 1. Check health
  const health = await client.getHealth();
  console.log('Status:', health.status);

  // 2. Fetch daily index series
  const series = await client.getDailyIndex(14);
  console.log('Index Series:', series);

  // 3. Survey route with statutory decomposition
  const quotes = await client.surveyRoute('DEL-BOM', 7);
  console.log('Quotes Decomposed:', quotes);
}

main();
```
