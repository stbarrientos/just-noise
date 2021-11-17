# frozen_string_literal: true

require 'rails_helper'

RSpec.describe AuthenticationService do
  let!(:user) { create(:user) }
  let(:service) { AuthenticationService.new(user) }

  describe '#self.find_and_sign_in' do
    before(:each) do
      allow(AuthenticationService).to receive(:sign_in).and_return true
    end

    context 'user match exists' do
      it 'retrieves user and calls sign in' do
        expect(AuthenticationService).to receive(:sign_in)
        AuthenticationService.find_and_sign_in(email: user.email, password: 'irrelevant')
      end
    end

    context 'user match does not exist' do
      it 'raises email not found error' do
        expect do
          AuthenticationService.find_and_sign_in(email: 'not@validemail.com', password: 'irrelevant')
        end.to raise_exception(AuthenticationService::InvalidCredentialsError::InvalidEmailError)
      end
    end
  end

  describe '#self.sign_in' do
    it 'raise is the password is not valid' do
      expect do
        AuthenticationService.sign_in(user: user, password: 'invalid')
      end.to raise_exception(AuthenticationService::InvalidCredentialsError::InvalidPasswordError)

      expect(user.reload.auth_token).to be_nil
      expect(user.last_sign_in).to be_nil
    end

    it 'sets the auth token and last signed in fields on the user on success' do
      AuthenticationService.sign_in(user: user, password: 'password')
      expect(user.reload.auth_token).to_not be_nil
      expect(user.last_sign_in).to_not be_nil
    end

    it 'returns the user if the password is valid' do
      returned_user = AuthenticationService.sign_in(user: user, password: 'password')
      expect(returned_user.id).to eql(user.id)
    end

    it 'raises if the user is not able to save correctly' do
      expect_any_instance_of(User).to receive(:save).and_return(false)
      expect do
        AuthenticationService.sign_in(user: user, password: 'password')
      end.to raise_exception(AuthenticationService::MiscSignInError)
    end
  end

  describe '#self.valid_password?' do
    it 'returns true if the password matches the db' do
      res = AuthenticationService.valid_password?(user: user, password: 'password')
      expect(res).to eql(true)
    end

    it 'returns false if the password does not match the db' do
      res = AuthenticationService.valid_password?(user: user, password: 'incorrect')
      expect(res).to eql(false)
    end
  end

  describe '#self.sign_out' do
    it 'clears auth token' do
      AuthenticationService.sign_out(user)
      expect(user.reload.auth_token).to be_nil
    end

    it 'raises if the save is unsuccessful' do
      expect_any_instance_of(User).to receive(:save).and_return(false)
      expect do
        AuthenticationService.sign_out(user)
      end.to raise_exception(AuthenticationService::MiscSignOutError)
    end
  end

  describe '#self.signed_in?' do
    it 'returns true if sign in token is present' do
      user.update auth_token: 'asdf'
      expect(AuthenticationService.signed_in?(user)).to eql(true)
    end

    it 'returns false if sign in token is not present' do
      user.update auth_token: nil
      expect(AuthenticationService.signed_in?(user)).to eql(false)
    end
  end

  describe '#self.authenticate_token' do
    it 'raises if the token is malformed' do
      auth_token = JWT.encode({ bad_key: user.id }, Rails.application.secrets.secret_key_base)
      user.update auth_token: auth_token
      expect do
        AuthenticationService.authenticate_token(auth_token)
      end.to raise_exception(AuthenticationService::InvalidAuthToken::MalformedTokenError)
    end

    it 'raises if the token cannot be parsed' do
      auth_token = 'good luck parsing me lol'
      user.update auth_token: auth_token
      expect do
        AuthenticationService.authenticate_token(auth_token)
      end.to raise_exception(AuthenticationService::InvalidAuthToken::MalformedTokenError)
    end

    it 'raises if no user matches the token' do
      auth_token = JWT.encode({ user_id: user.id + 1 }, Rails.application.secrets.secret_key_base)
      user.update auth_token: auth_token
      expect do
        AuthenticationService.authenticate_token(auth_token)
      end.to raise_exception(AuthenticationService::InvalidAuthToken::UserNotFoundError)
    end

    it 'returns the matching user' do
      auth_token = JWT.encode({ user_id: user.id }, Rails.application.secrets.secret_key_base)
      user.update auth_token: auth_token
      res = AuthenticationService.authenticate_token(auth_token)
      expect(res.id).to eql(user.id)
    end
  end

  describe '#sign_in' do
    it 'generates sign in token and last sign in on user' do
      res = service.sign_in('password')
      expect(res.id).to eql(user.id)
      expect(user.reload.auth_token).to_not be_nil
      expect(user.last_sign_in).to_not be_nil
    end

    it 'raises on invalid password' do
      expect do
        service.sign_in('wrongpw')
      end.to raise_exception(AuthenticationService::InvalidCredentialsError::InvalidPasswordError)
      expect(user.reload.auth_token).to be_nil
      expect(user.last_sign_in).to be_nil
    end
  end

  describe '#sign_out' do
    it 'clears sign in token on user' do
      user.update auth_token: 'whatever'
      service.sign_out
      expect(user.reload.auth_token).to be_nil
    end

    it 'raises exception if record cannot be saved' do
      user.update auth_token: 'whatever'
      expect(user).to receive(:save).and_return(false)
      expect do
        service.sign_out
      end.to raise_exception(AuthenticationService::MiscSignOutError)
    end
  end

  describe '#signed_in?' do
    it 'returns true if sign in token is present' do
      user.update auth_token: 'asdf'
      expect(service.signed_in?).to eql(true)
    end

    it 'returns false if sign in token is not present' do
      user.update auth_token: nil
      expect(service.signed_in?).to eql(false)
    end
  end
end
