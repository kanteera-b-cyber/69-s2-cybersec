'use strict';

const { ValidationError } = require('@strapi/utils').errors;

const COMMON_PASSWORDS = [
  'password',
  'password1',
  'password123',
  'p@ssw0rd',
  'admin',
  'admin123',
  'root',
  'root123',
  '12345678',
  '123456789',
  '1234567890',
  'qwerty123',
  'qwertyuiop',
  'abcdefgh',
  'abc12345',
  'letmein',
  'iloveyou',
  'welcome123',
  'monkey123',
  'dragon123',
  '11111111',
  '00000000',
];

const assertStrongPassword = (password) => {
  if (!password || typeof password !== 'string') {
    throw new ValidationError('Please provide a new password');
  }

  if (password.length < 8 || password.length > 128) {
    throw new ValidationError('Password must be between 8 and 128 characters');
  }

  if (
    !/[a-z]/.test(password) ||
    !/[A-Z]/.test(password) ||
    !/[0-9]/.test(password) ||
    !/[^a-zA-Z0-9]/.test(password)
  ) {
    throw new ValidationError(
      'Password must contain at least one uppercase letter, one lowercase letter, one number and one special character'
    );
  }

  if (COMMON_PASSWORDS.includes(password.toLowerCase())) {
    throw new ValidationError('This password is too common and has been rejected');
  }
};

module.exports = { assertStrongPassword };