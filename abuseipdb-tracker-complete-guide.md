# AbuseIPDB Threat Tracker - Complete Build Guide
## Ember.js + GraphQL Cybersecurity Dashboard

> **Purpose:** Build a production-ready cybersecurity threat monitoring application using Ember.js and GraphQL, integrating AbuseIPDB for real IP threat intelligence.

---

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Project Overview](#project-overview)
3. [Backend Setup (GraphQL API)](#backend-setup)
4. [Frontend Setup (Ember.js)](#frontend-setup)
5. [Complete File Structure](#complete-file-structure)
6. [Deployment Guide](#deployment-guide)
7. [Resume Bullets](#resume-bullets)

---

## Prerequisites

### Required Software
```bash
# Node.js (v20 or higher)
node --version  # Should be v20+

# npm (comes with Node.js)
npm --version

# Ember CLI (install globally)
npm install -g ember-cli

# Git (for version control)
git --version
```

### API Keys Required
1. **AbuseIPDB API Key** (Free tier: 1,000 checks/day note: blacklist endpoint limited to 5/day on free tier)
   - Sign up: https://www.abuseipdb.com/account
   - Navigate to: Account → API → Create Key

---

## Project Overview

### Tech Stack
**Backend:**
- Node.js + Express
- Apollo Server v4 (GraphQL)
- AbuseIPDB API integration
- ip-api.com for geolocation (free, no key required)
- Axios for HTTP requests
- In-memory caching

**Frontend:**
- Ember.js 6.x (Octane edition)
- Embroider + Vite build pipeline
- @apollo/client (direct, no ember-apollo-client wrapper)
- Tailwind CSS v4 with PostCSS
- Pure CSS for component styling

### Features
- Real-time IP threat intelligence lookup
- Recent malicious IP feed (populated by user lookups)
- Threat severity stats
- Abuse confidence scoring
- Responsive dark cybersecurity UI

### Important Notes on Free Tier Limitations
- AbuseIPDB `/check` endpoint: 1,000/day (used for IP lookups — fine)
- AbuseIPDB `/blacklist` endpoint: only 5/day (too limited for dashboard use)
- **Solution:** `recentThreats` and `threatStats` are populated from an in-memory store of looked-up IPs, not the blacklist endpoint
- Geolocation via ip-api.com: 45 requests/minute, no daily limit

---

## Backend Setup

### Step 1: Create Backend Directory

```bash
mkdir abuseipdb-tracker
cd abuseipdb-tracker
mkdir server
cd server
npm init -y
```

### Step 2: Install Backend Dependencies

```bash
npm install express @apollo/server @apollo/server/express4 graphql axios cors dotenv
npm install --save-dev nodemon
```

### Step 3: Create `server/package.json`

```json
{
  "name": "abuseipdb-server",
  "version": "1.0.0",
  "description": "GraphQL API for AbuseIPDB Threat Intelligence",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "dev": "nodemon index.js"
  },
  "keywords": ["graphql", "cybersecurity", "abuseipdb"],
  "author": "Your Name",
  "license": "MIT",
  "dependencies": {
    "@apollo/server": "^4.0.0",
    "axios": "^1.6.0",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "express": "^4.18.2",
    "graphql": "^16.8.1"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}
```

### Step 4: Create `server/.env`

```env
PORT=4000
ABUSEIPDB_API_KEY=your_api_key_here
NODE_ENV=development
```

### Step 5: Create `server/index.js`

```javascript
const express = require('express');
const { ApolloServer } = require('@apollo/server');
const { expressMiddleware } = require('@apollo/server/express4');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();

// Simple in-memory cache
const cache = {
  data: {},
  set(key, value, ttlMinutes = 10) {
    this.data[key] = {
      value,
      expires: Date.now() + ttlMinutes * 60 * 1000
    };
  },
  get(key) {
    const entry = this.data[key];
    if (!entry) return null;
    if (Date.now() > entry.expires) {
      delete this.data[key];
      return null;
    }
    return entry.value;
  }
};

// In-memory store of recently checked IPs (populated by lookups)
const recentlyChecked = [];

// GraphQL Type Definitions
const typeDefs = `#graphql
  type Location {
    country: String!
    city: String
    lat: Float
    lng: Float
  }

  type ThreatIntelligence {
    ipAddress: String!
    abuseScore: Int!
    totalReports: Int!
    countryCode: String!
    usageType: String
    isWhitelisted: Boolean!
    lastReportedAt: String
    location: Location
    domain: String
    isp: String
    reports: [AbuseReport!]
  }

  type AbuseReport {
    reportedAt: String!
    comment: String!
    categories: [Int!]!
    reporterId: Int!
    reporterCountryCode: String
  }

  type RecentThreat {
    ipAddress: String!
    abuseScore: Int!
    totalReports: Int!
    countryCode: String!
    lastReportedAt: String!
  }

  type ThreatStats {
    totalThreatsTracked: Int!
    highRiskThreats: Int!
    mediumRiskThreats: Int!
    lowRiskThreats: Int!
    countriesAffected: Int!
  }

  type Query {
    threatIntelligence(ipAddress: String!): ThreatIntelligence!
    recentThreats(limit: Int, minScore: Int): [RecentThreat!]!
    threatStats: ThreatStats!
  }
`;

// GraphQL Resolvers
const resolvers = {
  Query: {
    threatIntelligence: async (_, { ipAddress }) => {
      try {
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(ipAddress)) {
          throw new Error('Invalid IP address format');
        }

        const abuseResponse = await axios.get(
          `https://api.abuseipdb.com/api/v2/check`,
          {
            params: {
              ipAddress,
              maxAgeInDays: 90,
              verbose: true
            },
            headers: {
              'Key': process.env.ABUSEIPDB_API_KEY,
              'Accept': 'application/json'
            }
          }
        );

        const data = abuseResponse.data.data;

        // Geolocation via ip-api.com (free, no key, 45 req/min)
        let location = null;
        try {
          const geoResponse = await axios.get(`http://ip-api.com/json/${ipAddress}`);
          if (geoResponse.data && geoResponse.data.status === 'success') {
            location = {
              country: geoResponse.data.country || 'Unknown',
              city: geoResponse.data.city || null,
              lat: geoResponse.data.lat || null,
              lng: geoResponse.data.lon || null
            };
          }
        } catch (geoError) {
          console.log('Geolocation lookup failed:', geoError.message);
          location = {
            country: data.countryCode || 'Unknown',
            city: null,
            lat: null,
            lng: null
          };
        }

        const reports = data.reports ? data.reports.slice(0, 10).map(report => ({
          reportedAt: report.reportedAt,
          comment: report.comment || 'No comment provided',
          categories: report.categories || [],
          reporterId: report.reporterId,
          reporterCountryCode: report.reporterCountryCode || null
        })) : [];

        const result = {
          ipAddress: data.ipAddress,
          abuseScore: data.abuseConfidenceScore,
          totalReports: data.totalReports,
          countryCode: data.countryCode || 'Unknown',
          usageType: data.usageType || 'Unknown',
          isWhitelisted: data.isWhitelisted,
          lastReportedAt: data.lastReportedAt || null,
          location,
          domain: data.domain || null,
          isp: data.isp || 'Unknown',
          reports
        };

        // Add to recently checked feed
        recentlyChecked.unshift({
          ipAddress: result.ipAddress,
          abuseScore: result.abuseScore,
          totalReports: result.totalReports,
          countryCode: result.countryCode,
          lastReportedAt: result.lastReportedAt || new Date().toISOString()
        });
        if (recentlyChecked.length > 50) recentlyChecked.pop();

        return result;
      } catch (error) {
        if (error.response) {
          throw new Error(`AbuseIPDB API Error: ${error.response.data.errors?.[0]?.detail || error.response.statusText}`);
        }
        throw new Error(`Failed to fetch threat data: ${error.message}`);
      }
    },

    // Populated from recentlyChecked — no blacklist API call needed
    recentThreats: async (_, { limit = 20, minScore = 0 }) => {
      return recentlyChecked
        .filter(t => t.abuseScore >= minScore)
        .slice(0, limit);
    },

    // Calculated from recentlyChecked — no blacklist API call needed
    threatStats: async () => {
      const high = recentlyChecked.filter(t => t.abuseScore >= 90).length;
      const medium = recentlyChecked.filter(t => t.abuseScore >= 50 && t.abuseScore < 90).length;
      const low = recentlyChecked.filter(t => t.abuseScore < 50).length;
      const uniqueCountries = new Set(recentlyChecked.map(t => t.countryCode).filter(Boolean));

      return {
        totalThreatsTracked: recentlyChecked.length,
        highRiskThreats: high,
        mediumRiskThreats: medium,
        lowRiskThreats: low,
        countriesAffected: uniqueCountries.size
      };
    }
  }
};

async function startServer() {
  const app = express();

  const server = new ApolloServer({
    typeDefs,
    resolvers,
  });

  await server.start();

  app.use(
    '/graphql',
    cors({
      origin: [
        'http://localhost:4200',
        'https://your-netlify-app.netlify.app' // update after deploying frontend
      ],
      credentials: true
    }),
    express.json(),
    expressMiddleware(server)
  );

  app.get('/health', (req, res) => {
    res.json({
      status: 'ok',
      message: 'AbuseIPDB GraphQL API is running',
      timestamp: new Date().toISOString()
    });
  });

  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () => {
    console.log(`🚀 Server ready at http://localhost:${PORT}/graphql`);
    console.log(`📊 Health check at http://localhost:${PORT}/health`);
  });
}

startServer().catch(error => {
  console.error('Failed to start server:', error);
  process.exit(1);
});
```

### Step 6: Create `server/.gitignore`

```
node_modules/
.env
.DS_Store
npm-debug.log
```

### Step 7: Test Backend

```bash
npm run dev
# Server running at http://localhost:4000/graphql
```

---

## Frontend Setup

### Step 1: Create Ember Application

```bash
cd ..
npx ember-cli new frontend --skip-git
cd frontend
```

### Step 2: Install Frontend Dependencies

```bash
# Apollo Client (direct — do NOT use ember-apollo-client, incompatible with Ember 6)
npm install @apollo/client graphql --save-dev

# Tailwind CSS v4
npm install tailwindcss@4 @tailwindcss/postcss --save-dev

# Chart.js (optional, for future visualizations)
npm install chart.js
```

> **Important:** Do NOT install `ember-apollo-client` or `ember-cli-postcss`. These are incompatible with Ember 6 + Embroider + Vite.

### Step 3: Create `frontend/ember-cli-build.js`

Required by Ember CLI even with the Vite build pipeline:

```javascript
'use strict';

const EmberApp = require('ember-cli/lib/broccoli/ember-app');

module.exports = function (defaults) {
  const app = new EmberApp(defaults, {});
  return require('@embroider/compat').compatBuild(app);
};
```

### Step 4: Update `frontend/vite.config.mjs`

```javascript
import { defineConfig } from 'vite';
import { extensions, classicEmberSupport, ember } from '@embroider/vite';
import { babel } from '@rollup/plugin-babel';

export default defineConfig({
  plugins: [
    classicEmberSupport(),
    ember(),
    babel({
      babelHelpers: 'runtime',
      extensions,
    }),
  ],
});
```

### Step 5: Create `frontend/postcss.config.mjs`

```javascript
export default {
  plugins: {
    '@tailwindcss/postcss': {},
  },
};
```

### Step 6: Update `frontend/app/styles/app.css`

```css
@import "tailwindcss";

@source "./app/**/*.{js,ts,hbs}";

body {
  background-color: #030712;
  color: #f1f5f9;
}

/* Threat score badge */
.threat-badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 700;
  font-family: monospace;
}

.threat-high {
  background-color: rgba(239, 68, 68, 0.2);
  color: #f87171;
  border: 1px solid rgba(239, 68, 68, 0.3);
}

.threat-medium {
  background-color: rgba(245, 158, 11, 0.2);
  color: #fbbf24;
  border: 1px solid rgba(245, 158, 11, 0.3);
}

.threat-low {
  background-color: rgba(16, 185, 129, 0.2);
  color: #34d399;
  border: 1px solid rgba(16, 185, 129, 0.3);
}

/* Loading spinner */
.spinner {
  display: inline-block;
  width: 20px;
  height: 20px;
  border: 2px solid #06b6d4;
  border-top-color: transparent;
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

/* Application Layout */
.app-wrapper {
  min-height: 100vh;
  background-color: #030712;
  color: #f1f5f9;
  display: flex;
  flex-direction: column;
}

.app-nav {
  background-color: #111827;
  border-bottom: 1px solid rgba(6, 182, 212, 0.3);
  box-shadow: 0 4px 24px rgba(6, 182, 212, 0.05);
  margin-bottom: 32px;
}

.app-nav-inner {
  max-width: 1280px;
  margin: 0 auto;
  padding: 16px 24px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.app-nav-brand {
  display: flex;
  align-items: center;
  gap: 12px;
}

.app-nav-icon {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  background-color: rgba(6, 182, 212, 0.15);
  border: 1px solid rgba(6, 182, 212, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.75rem;
  font-weight: 700;
  color: #06b6d4;
}

.app-nav-title {
  font-size: 1.1rem;
  font-weight: 700;
  color: #06b6d4;
  letter-spacing: 0.2em;
  text-transform: uppercase;
}

.app-nav-subtitle {
  font-size: 0.7rem;
  color: #4b5563;
  letter-spacing: 0.15em;
  text-transform: uppercase;
}

.app-main {
  width: 100%;
  max-width: 1280px;
  margin: 0 auto;
  padding: 0 24px;
  flex: 1;
  box-sizing: border-box;
}

.app-footer {
  margin-top: 64px;
  padding: 32px 24px;
  border-top: 1px solid #1f2937;
}

.app-footer-inner {
  max-width: 1280px;
  margin: 0 auto;
  text-align: center;
  font-size: 0.7rem;
  color: #374151;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  line-height: 2;
}

/* Dashboard */
.dashboard-wrapper {
  padding: 16px 0;
}

.dashboard-header {
  margin-bottom: 40px;
}

.dashboard-header-eyebrow {
  font-size: 0.7rem;
  font-weight: 600;
  color: #06b6d4;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  margin-bottom: 8px;
}

.dashboard-header-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #f1f5f9;
  letter-spacing: -0.02em;
  margin-bottom: 8px;
  line-height: 1.1;
}

.dashboard-header-title span {
  color: #06b6d4;
}

.dashboard-header-subtitle {
  font-size: 0.85rem;
  color: #4b5563;
  letter-spacing: 0.05em;
}

.dashboard-error {
  border: 1px solid rgba(239, 68, 68, 0.4);
  background-color: rgba(239, 68, 68, 0.1);
  color: #f87171;
  padding: 16px 24px;
  border-radius: 8px;
  margin-bottom: 32px;
  font-size: 0.85rem;
}

.dashboard-error-title {
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-bottom: 4px;
  font-size: 0.75rem;
}

.dashboard-grid {
  display: flex;
  flex-direction: row;
  gap: 24px;
  margin-bottom: 24px;
}

.dashboard-grid > div {
  flex: 1;
}

.dashboard-lookup {
  margin-bottom: 24px;
}

@media (max-width: 768px) {
  .dashboard-grid {
    flex-direction: column;
  }
  .dashboard-header-title {
    font-size: 1.75rem;
  }
}

/* Threat Stats Component */
.threat-stats {
  display: flex;
  flex-direction: column;
  gap: 12px;
  height: 100%;
}

.threat-stats-title {
  font-size: 0.75rem;
  font-weight: 600;
  color: #06b6d4;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  margin-bottom: 4px;
}

.threat-stats-card {
  background-color: #111827;
  border-radius: 8px;
  padding: 16px;
  transition: filter 0.2s;
  flex: 1;
}

.threat-stats-card:hover {
  filter: brightness(1.1);
}

.threat-stats-card-label {
  font-size: 0.7rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.15em;
  margin-bottom: 8px;
}

.threat-stats-card-value {
  font-family: monospace;
  font-size: 2rem;
  font-weight: 700;
}

.threat-stats-card--cyan { border: 1px solid rgba(6, 182, 212, 0.3); }
.threat-stats-card--cyan .threat-stats-card-label { color: #06b6d4; }
.threat-stats-card--cyan .threat-stats-card-value { color: #06b6d4; }

.threat-stats-card--red { border: 1px solid rgba(239, 68, 68, 0.3); }
.threat-stats-card--red .threat-stats-card-label { color: #f87171; }
.threat-stats-card--red .threat-stats-card-value { color: #f87171; }

.threat-stats-card--yellow { border: 1px solid rgba(245, 158, 11, 0.3); }
.threat-stats-card--yellow .threat-stats-card-label { color: #fbbf24; }
.threat-stats-card--yellow .threat-stats-card-value { color: #fbbf24; }

.threat-stats-card--green { border: 1px solid rgba(16, 185, 129, 0.3); }
.threat-stats-card--green .threat-stats-card-label { color: #34d399; }
.threat-stats-card--green .threat-stats-card-value { color: #34d399; }

.threat-stats-card--purple { border: 1px solid rgba(139, 92, 246, 0.3); }
.threat-stats-card--purple .threat-stats-card-label { color: #a78bfa; }
.threat-stats-card--purple .threat-stats-card-value { color: #a78bfa; }

/* Threat Feed Component */
.threat-feed {
  background-color: #111827;
  border: 1px solid rgba(6, 182, 212, 0.3);
  border-radius: 8px;
  padding: 24px;
  height: 100%;
  box-sizing: border-box;
}

.threat-feed-title {
  font-size: 0.75rem;
  font-weight: 600;
  color: #06b6d4;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  margin-bottom: 16px;
}

.threat-feed-list {
  display: flex;
  flex-direction: column;
}

.threat-feed-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 0;
  border-bottom: 1px solid #1f2937;
  transition: background-color 0.2s;
}

.threat-feed-item:last-child {
  border-bottom: none;
}

.threat-feed-ip {
  background: none;
  border: none;
  font-family: monospace;
  font-size: 0.875rem;
  font-weight: 600;
  color: #06b6d4;
  cursor: pointer;
  padding: 0;
  transition: color 0.2s;
}

.threat-feed-ip:hover {
  color: #22d3ee;
}

.threat-feed-meta {
  display: flex;
  gap: 16px;
  margin-top: 4px;
  font-size: 0.75rem;
  color: #6b7280;
}

.threat-feed-timestamp {
  font-size: 0.7rem;
  color: #4b5563;
  font-family: monospace;
}

.threat-feed-empty {
  text-align: center;
  padding: 40px 0;
  font-size: 0.85rem;
  color: #4b5563;
  letter-spacing: 0.1em;
}

/* IP Lookup Component */
.ip-lookup {
  background-color: #111827;
  border: 1px solid rgba(6, 182, 212, 0.3);
  border-radius: 8px;
  padding: 24px;
}

.ip-lookup-title {
  font-size: 0.75rem;
  font-weight: 600;
  color: #06b6d4;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  margin-bottom: 20px;
}

.ip-lookup-form {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
}

.ip-lookup-input-wrapper {
  flex: 1;
}

.ip-lookup-label {
  display: block;
  font-size: 0.75rem;
  color: #6b7280;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  margin-bottom: 8px;
}

.ip-lookup-input {
  width: 100%;
  padding: 10px 14px;
  background-color: #1f2937;
  border: 1px solid #374151;
  border-radius: 6px;
  color: #f1f5f9;
  font-family: monospace;
  font-size: 0.9rem;
  transition: border-color 0.2s;
  box-sizing: border-box;
}

.ip-lookup-input:focus {
  outline: none;
  border-color: #06b6d4;
  box-shadow: 0 0 0 2px rgba(6, 182, 212, 0.2);
}

.ip-lookup-input::placeholder { color: #4b5563; }
.ip-lookup-input:disabled { opacity: 0.5; cursor: not-allowed; }

.ip-lookup-button {
  padding: 10px 20px;
  background-color: #06b6d4;
  color: #030712;
  border: none;
  border-radius: 6px;
  font-weight: 700;
  font-size: 0.85rem;
  letter-spacing: 0.05em;
  cursor: pointer;
  transition: background-color 0.2s;
  white-space: nowrap;
  align-self: flex-end;
}

.ip-lookup-button:hover { background-color: #22d3ee; }
.ip-lookup-button:disabled { background-color: #374151; color: #6b7280; cursor: not-allowed; }

.ip-lookup-error {
  border: 1px solid rgba(239, 68, 68, 0.4);
  background-color: rgba(239, 68, 68, 0.1);
  color: #f87171;
  padding: 12px 16px;
  border-radius: 6px;
  margin-bottom: 20px;
  font-size: 0.85rem;
}

.ip-lookup-results {
  border-top: 1px solid #1f2937;
  padding-top: 20px;
}

.ip-lookup-results-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.ip-lookup-results-title {
  font-family: monospace;
  font-size: 1rem;
  font-weight: 600;
  color: #06b6d4;
}

.ip-lookup-clear {
  background: none;
  border: none;
  color: #6b7280;
  font-size: 0.75rem;
  cursor: pointer;
  text-transform: uppercase;
  letter-spacing: 0.1em;
}

.ip-lookup-clear:hover { color: #f1f5f9; }

.ip-lookup-stats {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-bottom: 20px;
}

.ip-lookup-stat {
  background-color: #1f2937;
  border: 1px solid #374151;
  border-radius: 6px;
  padding: 12px;
}

.ip-lookup-stat-label {
  font-size: 0.7rem;
  color: #6b7280;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-bottom: 6px;
}

.ip-lookup-stat-value {
  font-family: monospace;
  font-size: 1.75rem;
  font-weight: 700;
  color: #f1f5f9;
}

.ip-lookup-details {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
  margin-bottom: 20px;
}

.ip-lookup-detail-title {
  font-size: 0.7rem;
  color: #06b6d4;
  text-transform: uppercase;
  letter-spacing: 0.15em;
  margin-bottom: 12px;
}

.ip-lookup-detail-row {
  display: flex;
  justify-content: space-between;
  padding: 6px 0;
  border-bottom: 1px solid #1f2937;
  font-size: 0.85rem;
}

.ip-lookup-detail-key { color: #6b7280; }
.ip-lookup-detail-value { color: #f1f5f9; font-family: monospace; }

.ip-lookup-reports { margin-top: 20px; }

.ip-lookup-reports-title {
  font-size: 0.7rem;
  color: #06b6d4;
  text-transform: uppercase;
  letter-spacing: 0.15em;
  margin-bottom: 12px;
}

.ip-lookup-report-list {
  max-height: 260px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.ip-lookup-report-list::-webkit-scrollbar { width: 4px; }
.ip-lookup-report-list::-webkit-scrollbar-track { background: #1f2937; }
.ip-lookup-report-list::-webkit-scrollbar-thumb { background: #374151; border-radius: 2px; }

.ip-lookup-report-item {
  background-color: #1f2937;
  border: 1px solid #374151;
  border-radius: 6px;
  padding: 10px 12px;
}

.ip-lookup-report-meta {
  display: flex;
  justify-content: space-between;
  margin-bottom: 6px;
}

.ip-lookup-report-date { font-size: 0.7rem; color: #6b7280; font-family: monospace; }
.ip-lookup-report-country { font-size: 0.7rem; color: #06b6d4; }
.ip-lookup-report-comment { font-size: 0.8rem; color: #9ca3af; line-height: 1.4; }
```

### Step 7: Configure Apollo Client

Create `frontend/app/services/apollo.js`:

```javascript
import Service from '@ember/service';
import { ApolloClient, InMemoryCache, HttpLink } from '@apollo/client/core';
import config from 'frontend/config/environment';

export default class ApolloService extends Service {
  client = new ApolloClient({
    link: new HttpLink({
      uri: config.apollo.apiURL,
    }),
    cache: new InMemoryCache(),
  });

  query(options) {
    return this.client.query(options);
  }

  mutate(options) {
    return this.client.mutate(options);
  }
}
```

### Step 8: Update `frontend/config/environment.js`

```javascript
'use strict';

module.exports = function (environment) {
  const ENV = {
    modulePrefix: 'frontend',
    environment,
    rootURL: '/',
    locationType: 'history',

    apollo: {
      apiURL: environment === 'production'
        ? 'https://your-render-backend.onrender.com/graphql'
        : 'http://localhost:4000/graphql',
      requestCredentials: 'omit'
    },

    EmberENV: {
      EXTEND_PROTOTYPES: false,
      FEATURES: {}
    },

    APP: {}
  };

  if (environment === 'test') {
    ENV.locationType = 'none';
    ENV.APP.LOG_ACTIVE_GENERATION = false;
    ENV.APP.LOG_VIEW_LOOKUPS = false;
    ENV.APP.rootElement = '#ember-testing';
    ENV.APP.autoboot = false;
  }

  return ENV;
};
```

### Step 9: Update `frontend/app/app.js`

```javascript
import Application from '@ember/application';
import compatModules from '@embroider/virtual/compat-modules';
import Resolver from 'ember-resolver';
import loadInitializers from 'ember-load-initializers';
import config from 'frontend/config/environment';

export default class App extends Application {
  modulePrefix = config.modulePrefix;
  Resolver = Resolver.withModules(compatModules);
}

loadInitializers(App, config.modulePrefix, compatModules);
```

### Step 10: Update `frontend/app/router.js`

```javascript
import EmberRouter from '@ember/routing/router';
import config from 'frontend/config/environment';

export default class Router extends EmberRouter {
  location = config.locationType;
  rootURL = config.rootURL;
}

Router.map(function () {
  this.route('dashboard', { path: '/' });
});
```

### Step 11: Create GraphQL Queries

Create `frontend/app/gql/queries/threat-intelligence.js`:

```javascript
import { gql } from '@apollo/client/core';

export default gql`
  query ThreatIntelligence($ipAddress: String!) {
    threatIntelligence(ipAddress: $ipAddress) {
      ipAddress
      abuseScore
      totalReports
      countryCode
      usageType
      isWhitelisted
      lastReportedAt
      domain
      isp
      location {
        country
        city
        lat
        lng
      }
      reports {
        reportedAt
        comment
        categories
        reporterCountryCode
      }
    }
  }
`;
```

Create `frontend/app/gql/queries/recent-threats.js`:

```javascript
import { gql } from '@apollo/client/core';

export default gql`
  query RecentThreats($limit: Int, $minScore: Int) {
    recentThreats(limit: $limit, minScore: $minScore) {
      ipAddress
      abuseScore
      totalReports
      countryCode
      lastReportedAt
    }
  }
`;
```

Create `frontend/app/gql/queries/threat-stats.js`:

```javascript
import { gql } from '@apollo/client/core';

export default gql`
  query ThreatStats {
    threatStats {
      totalThreatsTracked
      highRiskThreats
      mediumRiskThreats
      lowRiskThreats
      countriesAffected
    }
  }
`;
```

### Step 12: Create Routes

Create `frontend/app/routes/application.js`:

```javascript
import Route from '@ember/routing/route';

export default class ApplicationRoute extends Route {}
```

Create `frontend/app/routes/dashboard.js`:

```javascript
import Route from '@ember/routing/route';
import { service } from '@ember/service';
import threatStats from 'frontend/gql/queries/threat-stats';
import recentThreats from 'frontend/gql/queries/recent-threats';

export default class DashboardRoute extends Route {
  @service apollo;

  async model() {
    try {
      const [stats, threats] = await Promise.all([
        this.apollo.query({
          query: threatStats,
          fetchPolicy: 'network-only'
        }),
        this.apollo.query({
          query: recentThreats,
          variables: { limit: 20, minScore: 0 },
          fetchPolicy: 'network-only'
        }),
      ]);

      return {
        stats: stats.data.threatStats,
        threats: threats.data.recentThreats
      };
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
      return {
        stats: null,
        threats: [],
        error: error.message
      };
    }
  }
}
```

### Step 13: Create Templates

Create `frontend/app/templates/application.hbs`:

```handlebars
<div class="app-wrapper">
  <nav class="app-nav">
    <div class="app-nav-inner">
      <div class="app-nav-brand">
        <div class="app-nav-icon">⬡</div>
        <span class="app-nav-title">Threat Tracker</span>
      </div>
      <div class="app-nav-subtitle">Powered by AbuseIPDB & GraphQL</div>
    </div>
  </nav>

  <main class="app-main">
    {{outlet}}
  </main>

  <footer class="app-footer">
    <div class="app-footer-inner">
      <p>Built with Ember.js, GraphQL, and CSS</p>
      <p>Data provided by AbuseIPDB API</p>
    </div>
  </footer>
</div>
```

Create `frontend/app/templates/dashboard.hbs`:

```handlebars
<div class="dashboard-wrapper">
  <header class="dashboard-header">
    <p class="dashboard-header-eyebrow">Live Intelligence Feed</p>
    <h1 class="dashboard-header-title">
      AbuseIPDB <span>Threat Tracker</span>
    </h1>
    <p class="dashboard-header-subtitle">
      Real-time cybersecurity threat intelligence powered by GraphQL
    </p>
  </header>

  {{#if @model.error}}
    <div class="dashboard-error" role="alert">
      <p class="dashboard-error-title">Error Loading Dashboard</p>
      <p>{{@model.error}}</p>
    </div>
  {{/if}}

  <div class="dashboard-grid">
    <div><ThreatStats @stats={{@model.stats}} /></div>
    <div><ThreatFeed @threats={{@model.threats}} /></div>
  </div>

  <div class="dashboard-lookup">
    <IpLookup />
  </div>
</div>
```

### Step 14: Create Components

Create `frontend/app/components/threat-stats.js`:

```javascript
import Component from '@glimmer/component';

export default class ThreatStatsComponent extends Component {
  get stats() {
    return this.args.stats || {
      totalThreatsTracked: 0,
      highRiskThreats: 0,
      mediumRiskThreats: 0,
      lowRiskThreats: 0,
      countriesAffected: 0
    };
  }
}
```

Create `frontend/app/components/threat-stats.hbs`:

```handlebars
<div class="threat-stats">
  <p class="threat-stats-title">Threat Statistics</p>

  <div class="threat-stats-card threat-stats-card--cyan">
    <p class="threat-stats-card-label">Total Tracked</p>
    <p class="threat-stats-card-value">{{this.stats.totalThreatsTracked}}</p>
  </div>

  <div class="threat-stats-card threat-stats-card--red">
    <p class="threat-stats-card-label">High Risk</p>
    <p class="threat-stats-card-value">{{this.stats.highRiskThreats}}</p>
  </div>

  <div class="threat-stats-card threat-stats-card--yellow">
    <p class="threat-stats-card-label">Medium Risk</p>
    <p class="threat-stats-card-value">{{this.stats.mediumRiskThreats}}</p>
  </div>

  <div class="threat-stats-card threat-stats-card--green">
    <p class="threat-stats-card-label">Low Risk</p>
    <p class="threat-stats-card-value">{{this.stats.lowRiskThreats}}</p>
  </div>

  <div class="threat-stats-card threat-stats-card--purple">
    <p class="threat-stats-card-label">Countries</p>
    <p class="threat-stats-card-value">{{this.stats.countriesAffected}}</p>
  </div>
</div>
```

Create `frontend/app/components/threat-feed.js`:

```javascript
import Component from '@glimmer/component';
import { action } from '@ember/object';

export default class ThreatFeedComponent extends Component {
  get threats() {
    return this.args.threats || [];
  }

  @action
  getThreatLevel(score) {
    if (score >= 75) return 'high';
    if (score >= 50) return 'medium';
    return 'low';
  }

  @action
  getThreatBadgeClass(score) {
    return `threat-badge threat-${this.getThreatLevel(score)}`;
  }

  @action
  copyIpAddress(ip) {
    navigator.clipboard.writeText(ip).then(() => {
      alert(`IP address ${ip} copied to clipboard`);
    });
  }
}
```

Create `frontend/app/components/threat-feed.hbs`:

```handlebars
<div class="threat-feed">
  <h3 class="threat-feed-title">Recent Malicious IPs</h3>

  {{#if this.threats.length}}
    <div class="threat-feed-list">
      {{#each this.threats as |threat|}}
        <div class="threat-feed-item">
          <div>
            <div style="display: flex; align-items: center; gap: 12px;">
              <button
                type="button"
                {{on "click" (fn this.copyIpAddress threat.ipAddress)}}
                class="threat-feed-ip"
                title="Click to copy"
                aria-label="Copy IP address {{threat.ipAddress}}"
              >
                {{threat.ipAddress}}
              </button>
              <span class={{this.getThreatBadgeClass threat.abuseScore}}>
                {{threat.abuseScore}}%
              </span>
            </div>
            <div class="threat-feed-meta">
              <span>{{threat.countryCode}}</span>
              <span>{{threat.totalReports}} reports</span>
            </div>
          </div>
          <div class="threat-feed-timestamp">{{threat.lastReportedAt}}</div>
        </div>
      {{/each}}
    </div>
  {{else}}
    <p class="threat-feed-empty">No threats yet. Look up an IP to populate the feed.</p>
  {{/if}}
</div>
```

Create `frontend/app/components/ip-lookup.js`:

```javascript
import Component from '@glimmer/component';
import { service } from '@ember/service';
import { tracked } from '@glimmer/tracking';
import { action } from '@ember/object';
import threatIntelligence from '../gql/queries/threat-intelligence';

export default class IpLookupComponent extends Component {
  @service apollo;
  @service router;

  @tracked ipAddress = '';
  @tracked threatData = null;
  @tracked isLoading = false;
  @tracked error = null;

  @action
  updateIpAddress(event) {
    this.ipAddress = event.target.value;
    this.error = null;
  }

  @action
  async lookupIp(event) {
    event.preventDefault();

    if (!this.ipAddress.trim()) {
      this.error = 'Please enter an IP address';
      return;
    }

    this.isLoading = true;
    this.error = null;
    this.threatData = null;

    try {
      const result = await this.apollo.query({
        query: threatIntelligence,
        variables: { ipAddress: this.ipAddress.trim() },
        fetchPolicy: 'network-only'
      });

      this.threatData = result.data.threatIntelligence;

      // Refresh dashboard route to update recentThreats feed
      this.router.refresh('dashboard');

    } catch (err) {
      this.error = err.message || 'Failed to lookup IP address';
      console.error('Lookup error:', err);
    } finally {
      this.isLoading = false;
    }
  }

  @action
  clearResults() {
    this.threatData = null;
    this.error = null;
    this.ipAddress = '';
  }

  get threatLevel() {
    if (!this.threatData) return null;
    const score = this.threatData.abuseScore;
    if (score >= 75) return 'high';
    if (score >= 50) return 'medium';
    return 'low';
  }

  get threatLevelText() {
    const level = this.threatLevel;
    if (level === 'high') return 'High Risk';
    if (level === 'medium') return 'Medium Risk';
    return 'Low Risk';
  }

  get threatBadgeClass() {
    return `threat-badge threat-${this.threatLevel}`;
  }
}
```

Create `frontend/app/components/ip-lookup.hbs`:

```handlebars
<div class="ip-lookup">
  <h2 class="ip-lookup-title">IP Threat Intelligence Lookup</h2>

  <form {{on "submit" this.lookupIp}} class="ip-lookup-form">
    <div class="ip-lookup-input-wrapper">
      <label for="ip-input" class="ip-lookup-label">Enter IP Address</label>
      <input
        id="ip-input"
        type="text"
        value={{this.ipAddress}}
        {{on "input" this.updateIpAddress}}
        placeholder="e.g., 118.25.6.39"
        class="ip-lookup-input"
        disabled={{this.isLoading}}
        aria-label="IP Address Input"
      />
    </div>
    <button
      type="submit"
      class="ip-lookup-button"
      disabled={{this.isLoading}}
      aria-label="Lookup IP Address"
    >
      {{#if this.isLoading}}
        <span class="spinner"></span> Analyzing...
      {{else}}
        Lookup IP
      {{/if}}
    </button>
  </form>

  {{#if this.error}}
    <div class="ip-lookup-error" role="alert">
      <strong>Error:</strong> {{this.error}}
    </div>
  {{/if}}

  {{#if this.threatData}}
    <div class="ip-lookup-results">
      <div class="ip-lookup-results-header">
        <span class="ip-lookup-results-title">{{this.threatData.ipAddress}}</span>
        <button type="button" class="ip-lookup-clear" {{on "click" this.clearResults}}>
          Clear
        </button>
      </div>

      <div class="ip-lookup-stats">
        <div class="ip-lookup-stat">
          <p class="ip-lookup-stat-label">Abuse Score</p>
          <p class="ip-lookup-stat-value">{{this.threatData.abuseScore}}%</p>
          <span class={{this.threatBadgeClass}}>{{this.threatLevelText}}</span>
        </div>
        <div class="ip-lookup-stat">
          <p class="ip-lookup-stat-label">Total Reports</p>
          <p class="ip-lookup-stat-value">{{this.threatData.totalReports}}</p>
        </div>
        <div class="ip-lookup-stat">
          <p class="ip-lookup-stat-label">Country</p>
          <p class="ip-lookup-stat-value" style="font-size: 1.2rem;">{{this.threatData.countryCode}}</p>
          <p style="font-size: 0.75rem; color: #6b7280;">{{this.threatData.location.country}}</p>
        </div>
        <div class="ip-lookup-stat">
          <p class="ip-lookup-stat-label">Whitelisted</p>
          <p class="ip-lookup-stat-value" style="font-size: 1.2rem; color: {{if this.threatData.isWhitelisted '#10b981' '#ef4444'}}">
            {{if this.threatData.isWhitelisted "Yes" "No"}}
          </p>
        </div>
      </div>

      <div class="ip-lookup-details">
        <div>
          <p class="ip-lookup-detail-title">Network Information</p>
          <div class="ip-lookup-detail-row">
            <span class="ip-lookup-detail-key">ISP</span>
            <span class="ip-lookup-detail-value">{{this.threatData.isp}}</span>
          </div>
          <div class="ip-lookup-detail-row">
            <span class="ip-lookup-detail-key">Usage Type</span>
            <span class="ip-lookup-detail-value">{{this.threatData.usageType}}</span>
          </div>
          {{#if this.threatData.domain}}
            <div class="ip-lookup-detail-row">
              <span class="ip-lookup-detail-key">Domain</span>
              <span class="ip-lookup-detail-value">{{this.threatData.domain}}</span>
            </div>
          {{/if}}
          {{#if this.threatData.location.city}}
            <div class="ip-lookup-detail-row">
              <span class="ip-lookup-detail-key">City</span>
              <span class="ip-lookup-detail-value">{{this.threatData.location.city}}</span>
            </div>
          {{/if}}
        </div>
        <div>
          <p class="ip-lookup-detail-title">Timeline</p>
          {{#if this.threatData.lastReportedAt}}
            <div class="ip-lookup-detail-row">
              <span class="ip-lookup-detail-key">Last Reported</span>
              <span class="ip-lookup-detail-value">{{this.threatData.lastReportedAt}}</span>
            </div>
          {{/if}}
        </div>
      </div>

      {{#if this.threatData.reports}}
        <div class="ip-lookup-reports">
          <p class="ip-lookup-reports-title">Recent Abuse Reports</p>
          <div class="ip-lookup-report-list">
            {{#each this.threatData.reports as |report|}}
              <div class="ip-lookup-report-item">
                <div class="ip-lookup-report-meta">
                  <span class="ip-lookup-report-date">{{report.reportedAt}}</span>
                  {{#if report.reporterCountryCode}}
                    <span class="ip-lookup-report-country">{{report.reporterCountryCode}}</span>
                  {{/if}}
                </div>
                <p class="ip-lookup-report-comment">{{report.comment}}</p>
              </div>
            {{/each}}
          </div>
        </div>
      {{/if}}
    </div>
  {{/if}}
</div>
```

---

## Running the Application

```bash
# Terminal 1 - Backend
cd server
npm run dev
# Runs on http://localhost:4000

# Terminal 2 - Frontend (run as Administrator on Windows for symlink support)
cd frontend
ember serve
# Runs on http://localhost:4200
```

---

## Deployment Guide

### Backend → Render (free)

1. Go to **render.com** → New → Web Service
2. Connect your GitHub repo, select the `server` folder as root directory
3. Configure:
   - **Build Command:** `npm install`
   - **Start Command:** `node index.js`
   - **Instance Type:** Free
4. Add environment variables:
   - `ABUSEIPDB_API_KEY` → your key
   - `NODE_ENV` → `production`
5. Deploy — you'll get a URL like `https://your-app.onrender.com`
6. Update CORS in `server/index.js` with your Netlify URL once you have it

### Frontend → Netlify (free)

1. Update `frontend/config/environment.js` production URL with your Render URL
2. Add `frontend/public/_redirects`:
   ```
   /*    /index.html   200
   ```
3. Go to **netlify.com** → Add new site → Import from Git
4. Configure:
   - **Base directory:** `frontend`
   - **Build command:** `npm run build`
   - **Publish directory:** `frontend/dist`
5. Deploy

---

## Common Issues & Fixes

| Issue | Fix |
|-------|-----|
| `ember-apollo-client` template processor error | Don't use it — use `@apollo/client` directly |
| Symlink permission error on Windows | Run terminal as Administrator or enable Developer Mode |
| `@warp-drive` crash | Remove all `@warp-drive/*` packages if not using EmberData |
| Apollo result not showing data | Use `result.data.threatIntelligence` not `result.threatIntelligence` |
| AbuseIPDB blacklist 429 error | Free tier limited to 5/day — use in-memory store instead |
| Geolocation 429 error | Switched from ipapi.co to ip-api.com (45 req/min, no daily limit) |
| Tailwind classes not generating | Use `@source` directive in app.css or write plain CSS classes |

---

## Resume Bullets

1. **"Developed real-time cybersecurity threat monitoring dashboard using Ember.js 6 and GraphQL, integrating AbuseIPDB API to analyze IP reputation data with threat severity scoring"**

2. **"Built custom Apollo Client service for Ember.js 6 + Embroider/Vite build pipeline, replacing incompatible addon with direct @apollo/client integration"**

3. **"Designed GraphQL schema and resolvers with in-memory caching to work within free API tier constraints, reducing redundant external API calls and improving performance"**

4. **"Created accessible, responsive dark-themed UI with pure CSS and Tailwind CSS v4, achieving consistent cross-browser rendering without framework dependencies"**

5. **"Deployed full-stack application with Ember.js frontend on Netlify and Node.js/Apollo GraphQL backend on Render, configuring CORS and environment-based API routing"**

### Technical Skills
- **Frontend:** Ember.js 6, Glimmer Components, Embroider, Vite
- **API:** GraphQL, Apollo Client/Server v4, RESTful API Integration
- **Styling:** Tailwind CSS v4, Pure CSS, Responsive Design
- **Backend:** Node.js, Express, Apollo Server v4
- **Deployment:** Netlify, Render
- **Domain:** Cybersecurity, Threat Intelligence, IP Reputation Analysis