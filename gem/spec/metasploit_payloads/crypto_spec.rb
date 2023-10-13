require 'spec_helper'
require 'metasploit-payloads'

RSpec.describe ::MetasploitPayloads::Crypto do
  describe '#encrypt' do
    let(:encrypted_header) { ::MetasploitPayloads::Crypto::ENCRYPTED_PAYLOAD_HEADER }
    let(:plaintext) { "Hello World!".b }
    let(:ciphertext) { encrypted_header + "\\c\xB6N\x95\xE58\x8D\xDF\xBF4c".b }

    it 'can encrypt plaintext' do
      expect(described_class.encrypt(plaintext: plaintext)).to eq ciphertext
    end

    it 'can decrypt ciphertext' do
      expect(described_class.decrypt(ciphertext: ciphertext)).to eq plaintext
    end

    it 'is idempotent' do
      expect(described_class.decrypt(ciphertext: described_class.encrypt(plaintext: plaintext))).to eq plaintext
    end
  end
end
