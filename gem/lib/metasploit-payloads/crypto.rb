require 'openssl'

module MetasploitPayloads
  module Crypto
    CIPHERS = {
      1 => {
        name: 'chacha20'.b,
        version: { iv: 1, key: 1 },
        ivs: {
          1 => {
            value: "\x52\x25\xd7\xab\x52\x8f\x3f\xf8\x94\x97\x08\x42\x33\xb9\xd3\xb6".b # 16 bytes
          }
        },
        keys: {
          1 => {
            value: "\x28\x39\x97\x4c\x95\x11\x9d\x42\x6c\x8b\xff\x43\x3e\x5d\x3c\x33\x1b\x95\xd3\xea\xeb\xc9\xae\x71\x0a\x36\xe7\x98\x3d\x9d\x09\x52".b, # 32 bytes
          }
        }
      },
      2 => {
        name: 'aes-256-cbc'.b,
        version: { iv: 1, key: 1 },
        ivs: {
          1 => {
            value: "\x3c\x09\x85\x95\x19\x09\x10\xff\x76\xf0\x48\xf7\x21\x1a\x5c\x59".b, # 16 bytes
          }
        },
        keys: {
          1 => {
            value: "\x01\x93\x90\xfb\x84\xcd\x70\x16\x90\x1d\xc6\xf4\xf2\xfd\xcf\x59\xc4\x9c\x26\x35\x29\x67\x8c\x2d\x17\xb9\x35\xcb\x7d\xb0\x88\x7a".b, # 32 bytes
          }
        }
      }
    }.freeze
    CIPHER_VERSION = 2
    CURRENT_CIPHER = CIPHERS[CIPHER_VERSION]
    KEY_VERSION = CURRENT_CIPHER[:version][:key]
    IV_VERSION = CURRENT_CIPHER[:version][:iv]

    # Binary String, unsigned char, unsigned char, unsigned char
    ENCRYPTED_PAYLOAD_HEADER = ['msf', CIPHER_VERSION, IV_VERSION, KEY_VERSION].pack('A*CCC').freeze

    private_constant :CIPHERS
    private_constant :CURRENT_CIPHER
    private_constant :CIPHER_VERSION
    private_constant :KEY_VERSION
    private_constant :IV_VERSION

    def self.encrypt(plaintext: '')
      raise ::ArgumentError, 'Unable to encrypt plaintext: ' << plaintext, caller unless plaintext.to_s

      cipher = ::OpenSSL::Cipher.new(CURRENT_CIPHER[:name])

      cipher.encrypt
      cipher.iv = CURRENT_CIPHER[:ivs][IV_VERSION][:value]
      cipher.key = CURRENT_CIPHER[:keys][KEY_VERSION][:value]

      output = ENCRYPTED_PAYLOAD_HEADER.dup
      output << cipher.update(plaintext)
      output << cipher.final

      output
    end

    def self.decrypt(ciphertext: '')
      raise ::ArgumentError, 'Unable to decrypt ciphertext: ' << ciphertext, caller unless ciphertext.to_s

      return ciphertext unless ciphertext.start_with?('msf'.b)

      # Use the correct algorithm based on the version in the header
      msf_header, cipher_version, iv_version, key_version = ciphertext.unpack('A3CCC')

      current_cipher = CIPHERS[cipher_version]
      cipher = ::OpenSSL::Cipher.new(current_cipher[:name])
      iv = current_cipher[:ivs][iv_version][:value]
      key = current_cipher[:keys][key_version][:value]

      cipher.decrypt
      cipher.iv = iv
      cipher.key = key

      header = [msf_header, cipher_version, iv_version, key_version].pack('A*CCC').b
      # Remove encrypted header
      ciphertext = ciphertext.sub(header, '')

      output = cipher.update(ciphertext)
      output << cipher.final

      output
    end
  end
end
