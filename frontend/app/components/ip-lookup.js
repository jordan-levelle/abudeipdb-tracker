import Component from '@glimmer/component';
import { service } from '@ember/service';
import { tracked } from '@glimmer/tracking';
import { action } from '@ember/object';
import threatIntelligenceQuery from '../gql/queries/threat-intelligence';
import recentThreats from '../gql/queries/recent-threats';

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
        query: threatIntelligenceQuery,
        variables: { ipAddress: this.ipAddress.trim() },
        fetchPolicy: 'network-only'
      });

      console.log('Apollo result:', result);
      
      this.threatData = result.data.threatIntelligence;

      this.router.refresh('dashboard');

      await this.apollo.query({
        query: recentThreats,
        variables: { limit: 20, minScore: 0 },
        fetchPolicy: 'network-only'
      });
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
    const level = this.threatLevel;
    return `threat-badge threat-${level}`;
  }
}