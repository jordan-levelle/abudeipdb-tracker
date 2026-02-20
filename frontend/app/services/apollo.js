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