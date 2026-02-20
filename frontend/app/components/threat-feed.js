import Component from '@glimmer/component';
import { action } from '@ember/object';

export default class ThreatFeedComponent extends Component {
    get threats() {
        return this.args.threats || [];
    }

    @action
    getThreatDetails(score) {
        if (score >= 75) return 'High Risk';
        if (score >= 50) return 'Medium Risk';
        return 'low Risk';
    }

    @action
    getThreatBadgeClass(score) {
        const level = this.getThreatDetails(score);
        return `threat-badge threat-${level.toLowerCase()}`;
    }

    @action
    copyIpAddress(ip) {
        navigator.clipboard.writeText(ip).then(() => {
            alert(`IP address ${ip} copied to clipboard!`);
        }).catch(err => {
            console.error('Failed to copy IP address:', err);
            alert('Failed to copy IP address. Please try again.');
        });
    }
}
