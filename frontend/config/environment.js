'use strict';

module.exports = function (environment) {
  const ENV = {
    modulePrefix: 'frontend',
    environment,
    rootURL: '/',
    locationType: 'history',
    
    // Apollo Client Configuration
    apollo: {
      apiURL: environment === 'production' 
        ? 'https://your-backend-api.herokuapp.com/graphql'
        : 'http://localhost:4000/graphql',
      requestCredentials: 'same-origin'
    },

    EmberENV: {
      EXTEND_PROTOTYPES: false,
      FEATURES: {
        // Enable features here
      }
    },

    APP: {
      // App-specific config
    }
  };

  if (environment === 'development') {
    // Development-specific config
  }

  if (environment === 'test') {
    ENV.locationType = 'none';
    ENV.APP.LOG_ACTIVE_GENERATION = false;
    ENV.APP.LOG_VIEW_LOOKUPS = false;
    ENV.APP.rootElement = '#ember-testing';
    ENV.APP.autoboot = false;
  }

  if (environment === 'production') {
    // Production-specific config
  }

  return ENV;
};
