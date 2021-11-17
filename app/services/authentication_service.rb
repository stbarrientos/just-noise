# frozen_string_literal: true

# This service is in charge of authenticating users
# This service can be instantiated with a user object, or use class methods with a user as an argument
# DESIGN: because users don't need to know about the details of our authentication flow (only controllers care), this is
#   delegated outside of the model into its own service
class AuthenticationService

  # Error sub-classes
  class MiscSignInError < StandardError; end
  class MiscSignOutError < StandardError; end
  class InvalidCredentialsError < StandardError
    class InvalidEmailError < StandardError; end
    class InvalidPasswordError < StandardError; end
  end
  class InvalidAuthToken < StandardError
    class MalformedTokenError < StandardError; end
    class UserNotFoundError < StandardError; end
  end

  # Find the user by the given email and sign in
  # If the user email cannot be found, raise
  def self.find_and_sign_in(email:, password:)
    user = User.find_by(email: email)
    raise InvalidCredentialsError::InvalidEmailError if user.nil?

    sign_in(user: user, password: password)
  end

  # If the password is incorrect, raise
  # If the user record cannot be signed in (corrupted / invalid record), raise
  def self.sign_in(user:, password:)
    raise InvalidCredentialsError::InvalidPasswordError unless valid_password?(user: user, password: password)

    user.last_sign_in = Time.now.utc
    user.auth_token = JWT.encode({ user_id: user.id }, Rails.application.secrets.secret_key_base)
    raise MiscSignInError unless user.save

    user
  end

  # Check the provided password against the password stored in the db
  def self.valid_password?(user:, password:)
    # authenticate method provided by bcrypt
    # It looks like an anti-pattern to have a model#authenticate in the authentication service, but other than comparing
    # encrypted strings we don't want the model to have any other responsibility
    (user.authenticate password).present?
  end

  # Clear the user's auth token
  # If the user cannot be updated, raise
  def self.sign_out(user)
    raise MiscSignOutError unless user.update auth_token: nil

    user
  end

  # Check if the user is currently signed in
  def self.signed_in?(user)
    user.auth_token.present?
  end

  # Given a token, search for the owning user
  def self.authenticate_token(token)
    # Inspired by this article
    # https://www.pluralsight.com/guides/token-based-authentication-with-ruby-on-rails-5-api
    # We just want to decode the token
    decoded_token = nil
    begin
      decoded_token = HashWithIndifferentAccess.new(JWT.decode(token, Rails.application.secrets.secret_key_base)[0])
    rescue StandardError
      raise InvalidAuthToken::MalformedTokenError
    end

    # If the token is malformed, raise
    raise InvalidAuthToken::MalformedTokenError if decoded_token[:user_id].nil?

    # User find_by because we don't want active record's errors on #find
    user = User.find_by(id: decoded_token[:user_id])
    # If no user owns that token, raise
    raise InvalidAuthToken::UserNotFoundError if user.nil?

    user
  end

  ##### INSTANCE METHODS #####
  # These instance methods exist to give a cleaner API when working with one object continuously
  # These methods do not reimplement the class methods, merely use them under the hood
  ############################

  def initialize(user)
    @user = user
  end

  def sign_in(password)
    self.class.sign_in user: @user, password: password
  end

  def sign_out
    self.class.sign_out @user
  end

  def signed_in?
    self.class.signed_in? @user
  end
end
