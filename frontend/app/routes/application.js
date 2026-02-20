import Route from '@ember/routing/route';
import { service } from '@ember/service';

export default class ApplicationRoute extends Route {
    @service apollo;

    async beforeModel() {
        try {
            await this.apollo.client;
        } catch (error) {
            console.error('Error initializing Apollo Client:', error);
        }
    }
}
