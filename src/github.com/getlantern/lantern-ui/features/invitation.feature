Feature: Invite a friend

  As growth hack, we encourage people to invite friends by adding one free month for both inviter and invitee once both of them upgraded to Pro.

  Background:
    Given Lantern is running

  Scenario: Invite a friend
    When I click the invite link
    Then a promotion code will be shown
    And various sharing options will be shown

  Scenario: Invite via email
  When I input the email accounts
  Then email will sent
