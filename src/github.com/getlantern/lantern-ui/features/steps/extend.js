var steps = function() {

  this.When(/^my subscription will end in one month$/, function (callback) {
    // Write code here that turns the phrase above into concrete actions
    callback.pending();
  });

  this.Then(/^an email will be sent to me to extend$/, function (callback) {
    // Write code here that turns the phrase above into concrete actions
    callback.pending();
  });

  this.Then(/^popup will be shown if user didn't click the link and open Lantern in (\d+) days before expires$/, function (arg1, callback) {
    // Write code here that turns the phrase above into concrete actions
    callback.pending();
  });
};

module.exports = steps;
