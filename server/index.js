const express = require('express');
const { ApolloServer } = require('@apollo/server');
const { expressMiddleware } = require('@apollo/server/express4');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();

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

const cache = {
  data: {},
  set(key, value, ttlMinutes = 10) {
    this.data[key] = { value, 
      expiresAt: Date.now() + ttlMinutes * 60 * 1000 
    };
  },
  get(key) {
    const entry = this.data[key];
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      delete this.data[key];
      return null;
    }
    return entry.value;
  }
}

// GraphQL Resolvers
// In-memory store of recently checked IPs
const recentlyChecked = [];

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

        let location = null;
        try {
          const geoResponse = await axios.get(`https://ipapi.co/${ipAddress}/json/`);
          if (geoResponse.data && !geoResponse.data.error) {
            location = {
              country: geoResponse.data.country_name || 'Unknown',
              city: geoResponse.data.city || null,
              lat: geoResponse.data.latitude || null,
              lng: geoResponse.data.longitude || null
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

        // Store in recently checked feed
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

    recentThreats: async (_, { limit = 20, minScore = 0 }) => {
      return recentlyChecked
        .filter(t => t.abuseScore >= minScore)
        .slice(0, limit);
    },

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


// Start Apollo Server v4
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
      origin: ['http://localhost:4200', 'http://localhost:7020'],
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

  app.get('/', (req, res) => {
    res.json({ 
      message: 'AbuseIPDB Threat Tracker API',
      endpoints: {
        graphql: '/graphql',
        health: '/health'
      }
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