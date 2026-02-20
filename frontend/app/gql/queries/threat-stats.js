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