#include "metsrv.h"
#include "../../common/common.h"
#include "server_pivot.h"
#include "server_pivot_named_pipe.h"

/*!
 * @brief Add a pivot point to the current meterpreter session
 * @remote Pointer to the \c Remote instance.
 * @remote Pointer to the incoming request \c Packet instance.
 * @return Indication of error or success.
 * @remark This allows for meterpreter to become a staging and pivot point
 *         for other Meterpreter instances on the network.
 */
DWORD request_core_pivot_add(Remote* remote, Packet* packet)
{
	// Right now we only support named pipe pivotes, so just go straight there
	return request_core_pivot_add_named_pipe(remote, packet);
}