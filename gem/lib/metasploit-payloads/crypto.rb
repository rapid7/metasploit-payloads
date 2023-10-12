require 'openssl'

module MetasploitPayloads
  module Crypto
    CIPHER_NAME = 'chacha20'.freeze
    IV = 'EncryptedPayload'.freeze # 16 bytes
    KEY = 'Rapid7MetasploitEncryptedPayload'.freeze # 32 bytes
    ENCRYPTED_PAYLOAD_HEADER = 'encrypted_payload_chacha20_v1'.freeze

    def self.encrypt(plaintext: '')
      raise ::ArgumentError, 'Unable to encrypt plaintext: ' << plaintext, caller unless plaintext.to_s

      cipher = ::OpenSSL::Cipher.new(CIPHER_NAME)

      cipher.encrypt
      cipher.iv = IV
      cipher.key = KEY

      output = ENCRYPTED_PAYLOAD_HEADER.dup
      output << cipher.update(plaintext)
      output << cipher.final

      output
    end

    def self.decrypt(ciphertext: '')
      raise ::ArgumentError, 'Unable to decrypt ciphertext: ' << ciphertext, caller unless ciphertext.to_s

      cipher = ::OpenSSL::Cipher.new(CIPHER_NAME)

      cipher.decrypt
      cipher.iv = IV
      cipher.key = KEY

      # Remove encrypted header if present
      ciphertext = ciphertext.sub(ENCRYPTED_PAYLOAD_HEADER, '')

      output = cipher.update(ciphertext)
      output << cipher.final

      output
    end
  end
end