# -*- coding:binary -*-

require 'metasploit-payloads/version' unless defined? MetasploitPayloads::VERSION

module MetasploitPayloads

  EXTENSION_PREFIX      = 'ext_server_'
  METERPRETER_SUBFOLDER = 'meterpreter'

  #
  # Get the path to an extension based on its name (no prefix).
  #
  def self.meterpreter_ext_path(ext_name, binary_suffix)
    path("#{EXTENSION_PREFIX}#{ext_name}", binary_suffix)
  end

  #
  # Get the path to a meterpreter binary by full name.
  #
  def self.meterpreter_path(name, binary_suffix)
    file_name = "#{name}.#{binary_suffix}".downcase
    root_dirs = [local_meterpreter_dir]

    # Try the data folder first to see if the extension exists, as this
    # allows for the MSF data/meterpreter folder to override what is
    # in the gem. This is very helpful for testing/development without
    # having to move the binaries to the gem folder each time. We only
    # do this is MSF is installed.
    root_dirs.unshift(msf_meterpreter_dir) if metasploit_installed?

    until root_dirs.length.zero?
      file_path = expand(root_dirs.shift, file_name)
      return file_path if ::File.readable?(file_path)
    end

    nil
  end

  #
  # Get the full path to any file packaged in this gem by local path and name.
  #
  def self.path(*path_parts)
    root_dirs = [data_directory]

    # Same as above, we try the data folder first, the fall back to the local
    # meterpreter folder
    root_dirs.unshift(Msf::Config.data_directory) if metasploit_installed?

    until root_dirs.length.zero?
      file_path = expand(root_dirs.shift, ::File.join(path_parts))
      return file_path if ::File.readable?(file_path)
    end

    nil
  end

  #
  # Get the contents of any file packaged in this gem by local path and name.
  #
  def self.read(*path_parts)
    file_path = path(path_parts)
    if file_path.nil?
      full_path = ::File.join(path_parts)
      raise RuntimeError, "#{full_path} not found", caller
    end

    ::File.open(file_path, "rb" ) { |f|
      f.read(f.stat.size)
    }
  end

  #
  # List all the available extensions for the given suffix.
  #
  def self.list_meterpreter_extensions(binary_suffix)
    extensions = []

    root_dirs = [local_meterpreter_dir]
    # Find the valid extensions in the data folder first, if MSF
    # is installed.
    root_dirs.unshift(msf_meterpreter_dir) if metasploit_installed?

    until root_dirs.length.zero?
      # Merge in any that don't already exist in the collection.
      meterpreter_enum_ext(root_dirs.shift, binary_suffix).each do |e|
        extensions.push(e) unless extensions.include?(e)
      end
    end

    extensions
  end

private

  #
  # Determine if MSF has been installed and is being used.
  #
  def self.metasploit_installed?
    defined? Msf::Config
  end

  #
  # Full path to the local gem folder containing the base data
  #
  def self.data_directory
    ::File.join(::File.dirname(__FILE__), '..', 'data')
  end

  #
  # Full path to the MSF data folder which contains the meterpreter binaries.
  #
  def self.msf_meterpreter_dir
    ::File.join(Msf::Config.data_directory, METERPRETER_SUBFOLDER)
  end

  #
  # Full path to the local gem folder which contains the meterpreter binaries.
  #
  def self.local_meterpreter_dir
    ::File.join(data_directory, METERPRETER_SUBFOLDER)
  end

  #
  # Full path to the MSF data folder which contains the binaries.
  #
  def self.msf_meterpreter_dir
    ::File.join(Msf::Config.data_directory, METERPRETER_SUBFOLDER)
  end

  #
  # Enumerate extensions in the given root folder based on the suffix.
  #
  def self.meterpreter_enum_ext(root_dir, binary_suffix)
    exts = []
    ::Dir.entries(root_dir).each do |f|
      if (::File.readable?(::File.join(root_dir, f)) && f =~ /#{EXTENSION_PREFIX}(.*)\.#{binary_suffix}/)
        exts.push($1)
      end
    end
    exts
  end

  #
  # Expand the given root path and file name into a full file location.
  #
  def self.expand(root_dir, file_name)
    ::File.expand_path(::File.join(root_dir, file_name))
  end

end

