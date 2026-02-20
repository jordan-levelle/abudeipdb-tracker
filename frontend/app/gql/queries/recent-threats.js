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