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
