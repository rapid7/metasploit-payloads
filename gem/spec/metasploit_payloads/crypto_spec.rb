require 'spec_helper'
require 'metasploit-payloads'

RSpec.describe ::MetasploitPayloads::Crypto do
  describe '#encrypt' do
    let(:encrypted_header) { ::MetasploitPayloads::Crypto::ENCRYPTED_PAYLOAD_HEADER }
    let(:plaintext) { "Hello World!".b }
    let(:ciphertext) { encrypted_header + "F=\xF9\xCB\xF6\xA1\xE4h\x89\x96DD\xC0+\x04\xF1".b }

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
