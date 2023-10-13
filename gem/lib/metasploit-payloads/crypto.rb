require 'openssl'

module MetasploitPayloads
  module Crypto
    CIPHERS = {
      chacha20: {
        name: 'chacha20'.b,
        version: 1,
        iv: {
          value: 'EncryptedPayload'.b, # 16 bytes
          version: 1
        },
        key: {
          value: 'Rapid7MetasploitEncryptedPayload'.b, # 32 bytes
          version: 1
        }
      }
    }.freeze
    CURRENT_CIPHER = CIPHERS[:chacha20]
    CIPHER_VERSION = CURRENT_CIPHER[:version]
    KEY_VERSION = CURRENT_CIPHER[:key][:version]
    IV_VERSION = CURRENT_CIPHER[:iv][:version]
    # Binary String, unsigned char, unsigned char, unsigned char
    ENCRYPTED_PAYLOAD_HEADER = ['msf', CIPHER_VERSION, IV_VERSION, KEY_VERSION].pack('A*CCC')

    private_constant :CIPHERS
    private_constant :CURRENT_CIPHER
    private_constant :CIPHER_VERSION
    private_constant :KEY_VERSION
    private_constant :IV_VERSION

    def self.encrypt(plaintext: '')
      raise ::ArgumentError, 'Unable to encrypt plaintext: ' << plaintext, caller unless plaintext.to_s

      cipher = ::OpenSSL::Cipher.new(CURRENT_CIPHER[:name])

      cipher.encrypt
      cipher.iv = CURRENT_CIPHER[:iv][:value]
      cipher.key = CURRENT_CIPHER[:key][:value]

      output = ENCRYPTED_PAYLOAD_HEADER.dup
      output << cipher.update(plaintext)
      output << cipher.final

      output
    end

    def self.decrypt(ciphertext: '')
      raise ::ArgumentError, 'Unable to decrypt ciphertext: ' << ciphertext, caller unless ciphertext.to_s

      cipher = ::OpenSSL::Cipher.new(CURRENT_CIPHER[:name])

      cipher.decrypt
      cipher.iv = CURRENT_CIPHER[:iv][:value]
      cipher.key = CURRENT_CIPHER[:key][:value]

      # Remove encrypted header if present
      ciphertext = ciphertext.sub(ENCRYPTED_PAYLOAD_HEADER, '')

      output = cipher.update(ciphertext)
      output << cipher.final

      output
    end
  end
end
