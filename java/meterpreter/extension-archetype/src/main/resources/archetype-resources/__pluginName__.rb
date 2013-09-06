module Rex
module Post
module Meterpreter
module Extensions
module ${pluginName.substring(0,1).toUpperCase()}${pluginName.substring(1)}

TLV_TYPE_GREETEE = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 1);

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

	def ${pluginName}_greet_world()
		request = Packet.create_request('${pluginName}_greet_world')
		response = client.send_request(request)
		return response.get_tlv_value(TLV_TYPE_STRING)
	end

	def ${pluginName}_greet_someone(greetee)
		request = Packet.create_request('${pluginName}_greet_someone')
		request.add_tlv(TLV_TYPE_GREETEE, greetee)
		response = client.send_request(request)
		return response.get_tlv_value(TLV_TYPE_STRING)
	end
end

end; end; end; end; end
