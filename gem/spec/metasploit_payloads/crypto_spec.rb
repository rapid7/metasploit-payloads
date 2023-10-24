require 'metasploit-payloads'

RSpec.describe ::MetasploitPayloads::Crypto do
  let(:plaintext) { "Hello World!".b }

  describe '#encrypt' do
    let(:encrypted_header) { "msf\x02\x01\x01".b }
    let(:ciphertext) { encrypted_header + "F=\xF9\xCB\xF6\xA1\xE4h\x89\x96DD\xC0+\x04\xF1".b }

    it 'encrypts using aes-256-cbc' do
      expect(described_class.encrypt(plaintext: plaintext)).to eq ciphertext
    end
  end

  describe '#decrypt' do
    context 'when the ciphertext is' do
      context 'encrypted with chacha20' do
        let(:encrypted_header) { "msf\x01\x01\x01".b }
        let(:ciphertext) { encrypted_header + "\x89:^r\xC1\xC9\xD9\xA1\xDC\xEB\xBFm".b }

        it 'returns plaintext' do
          expect(described_class.decrypt(ciphertext: ciphertext)).to eq plaintext
        end
      end

      context 'encrypted with aes-256-cbc' do
        let(:encrypted_header) { "msf\x02\x01\x01".b }
        let(:ciphertext) { encrypted_header + "F=\xF9\xCB\xF6\xA1\xE4h\x89\x96DD\xC0+\x04\xF1".b }

        it 'returns plaintext' do
          expect(described_class.decrypt(ciphertext: ciphertext)).to eq plaintext
        end
      end

      context 'not encrypted' do
        let(:ciphertext) { plaintext }

        it 'returns plaintext' do
          expect(described_class.decrypt(ciphertext: ciphertext)).to eq plaintext
        end
      end
    end
  end

  it 'is idempotent' do
    expect(described_class.decrypt(ciphertext: described_class.encrypt(plaintext: plaintext))).to eq plaintext
  end
end
