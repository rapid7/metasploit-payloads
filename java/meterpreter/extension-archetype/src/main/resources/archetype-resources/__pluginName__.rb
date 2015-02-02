# -*- coding: binary -*-

module Rex
  module Post
    module Meterpreter
      module Extensions
        # This module contains a 'Hello World' meterpreter extension
        module ${pluginName.substring(0,1).toUpperCase()}${pluginName.substring(1)}
          TLV_TYPE_GREETEE = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 1)

          # This class implements a 'Hello World' meterpreter extension
          class ${pluginName.substring(0,1).toUpperCase()}${pluginName.substring(1)} < Extension
            def initialize(client)
              super(client, '${pluginName}')

              client.register_extension_aliases(
                [
                  {
                    'name' => '${pluginName}',
                    'ext'  => self
                  }
                ])
            end

            # Sends a greet_world request and gets a reply
            #
            # @return [String]
            def ${pluginName}_greet_world
              request = Packet.create_request('${pluginName}_greet_world')
              response = client.send_request(request)
              response.get_tlv_value(TLV_TYPE_STRING)
            end

            # Sends a greet_someone request and gets a reply
            #
            # @return [String]
            def ${pluginName}_greet_someone(greetee)
              request = Packet.create_request('${pluginName}_greet_someone')
              request.add_tlv(TLV_TYPE_GREETEE, greetee)
              response = client.send_request(request)
              response.get_tlv_value(TLV_TYPE_STRING)
            end
          end
        end
      end
    end
  end
end
