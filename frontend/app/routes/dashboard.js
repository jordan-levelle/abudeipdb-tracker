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