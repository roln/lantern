// An example configuration file
exports.config = {
  //seleniumAddress: 'http://localhost:4444/wd/hub',
  capabilities: {
    'browserName': 'chrome'
  },
  baseUrl: "http://localhost:3000",
  specs: ['../features/*.feature'],
  framework: 'custom',
  frameworkPath: require.resolve('protractor-cucumber-framework'),
  cucumberOpts: {
    require: '../features/steps/**/*.js',
    format: "summary"
  }
};

