#include "metsrv.h"
#include "../../common/common.h"
#include "server_pivot.h"

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
	return 0;
}