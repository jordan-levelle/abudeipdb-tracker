import Component from '@glimmer/component';

export default class ThreatStatsComponent extends Component {
    get stats() {
        return this.args.stats || {
            totalThreatsTracked: 0,
            highRiskThreats: 0,
            mediumRiskThreats: 0,
            lowRiskThreats: 0,
            countriesAffected: 0,
        };
    }
};