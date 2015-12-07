Feature: Extend a subscription

  No matter if the subscription expired or not, Pro user can always extend by payment. The new expiry date will be the latest of the current expire date or current date, plus the extended period.

  Background:
    Given Lantern is running
    And I am a Pro user

  Scenario: Notification
  When my subscription will end in one month
  Then an email will be sent to me to extend
  And popup will be shown if user didn't click the link and open Lantern in 7 days before expires

  Scenario: Before expires

  Scenario: After expires

