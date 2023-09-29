# frozen_string_literal: true

module MetasploitPayloads
  class Error < StandardError
  end

  # Error raised when a Metasploit Payloads file doesn't exist.
  class NotFoundError < Error
    attr_reader :path

    def initialize(path = '')
      @path = path
      super("Meterpreter path #{@path} not found. Ensure antivirus is not enabled, or reinstall Metasploit.")
    end
  end

  # Error raised when the user does not have read permissions for a Metasploit Payloads file
  class NotReadableError < Error
    attr_reader :path

    def initialize(path = '')
      @path = path
      super("Meterpreter path #{@path} is not readable. Check if you have read access and try again.")
    end
  end

  # Error raised when a Metasploit Payloads file's hash does not match what is defined in the manifest file.
  class HashMismatchError < Error
    attr_reader :path

    def initialize(path = '')
      @path = path
      super("Meterpreter path #{@path} does not match the hash defined in the Metasploit Payloads manifest file.")
    end
  end
end
