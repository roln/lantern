Feature: Upgrade to Lantern Pro on desktop

  If user feels good about Lantern, there should be a way for them to
  upgrade to Pro as easily as possible.

  Background:
    Given Lantern is running

  Scenario: Proceed to payment
    When I click the upgrade link
    And I select a plan
    And I input my email address
    Then it will redirect me to payment page
    # The point here is to emphasis that which is the email address identifing user.
    # If user use a different email address for payment, he will notice it by having to change manually.
    And fill the email address automatically

  Scenario: Payment succeeded
    When I input my email address
    And I paid enough money
    Then I will be prompted
    And An confimation will sent to the supplied address

  Scenario: Payment failed

  Scenario: Have a friend to pay for me
