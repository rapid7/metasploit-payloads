/*!
 * @file bf.c
 * @brief Entry point and intialization definitions for the Brainfuck extension
 */

/*
 Brainfuck-C ( http://github.com/kgabis/brainfuck-c )
 Copyright (c) 2012 Krzysztof Gabis

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
*/

#include "../../common/common.h"
#include "../../DelayLoadMetSrv/DelayLoadMetSrv.h"
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

#define TLV_TYPE_EXTENSION_BF	0

#define TLV_TYPE_BF_CODE       MAKE_CUSTOM_TLV(TLV_META_TYPE_STRING, TLV_TYPE_EXTENSION_BF, TLV_EXTENSIONS + 1)
#define TLV_TYPE_BF_RESULT     MAKE_CUSTOM_TLV(TLV_META_TYPE_STRING, TLV_TYPE_EXTENSION_BF, TLV_EXTENSIONS + 2)

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

static BOOL gSuccessfullyLoaded = FALSE;

#define OP_END          0
#define OP_INC_DP       1
#define OP_DEC_DP       2
#define OP_INC_VAL      3
#define OP_DEC_VAL      4
#define OP_OUT          5
#define OP_IN           6
#define OP_JMP_FWD      7
#define OP_JMP_BCK      8

#define PROGRAM_SIZE    4096
#define STACK_SIZE      512
#define OUT_SIZE        512
#define DATA_SIZE       65535

#define STACK_PUSH(A)   (ctx->s[ctx->sp++] = A)
#define STACK_POP()     (ctx->s[--ctx->sp])
#define STACK_EMPTY()   (ctx->sp == 0)
#define STACK_FULL()    (ctx->sp == STACK_SIZE)

struct instruction_t {
    unsigned short operator;
    unsigned short operand;
};

struct bf_ctx {
	struct instruction_t p[PROGRAM_SIZE];
	unsigned short s[STACK_SIZE];
	unsigned int sp;
	unsigned int outp;
	char out[OUT_SIZE];
};

int compile_bf(char *code, struct bf_ctx *ctx)
{
    unsigned short pc = 0, jmp_pc;
    int c;
    while ((c = *code++) != '\0' && pc < PROGRAM_SIZE) {
        switch (c) {
            case '>': ctx->p[pc].operator = OP_INC_DP; break;
            case '<': ctx->p[pc].operator = OP_DEC_DP; break;
            case '+': ctx->p[pc].operator = OP_INC_VAL; break;
            case '-': ctx->p[pc].operator = OP_DEC_VAL; break;
            case '.': ctx->p[pc].operator = OP_OUT; break;
            case ',': ctx->p[pc].operator = OP_IN; break;
            case '[':
                ctx->p[pc].operator = OP_JMP_FWD;
                if (STACK_FULL()) {
                    return ERROR_NOT_ENOUGH_MEMORY;
                }
                STACK_PUSH(pc);
                break;
            case ']':
                if (STACK_EMPTY()) {
                    return ERROR_NOT_ENOUGH_MEMORY;
                }
                jmp_pc = STACK_POP();
                ctx->p[pc].operator =  OP_JMP_BCK;
                ctx->p[pc].operand = jmp_pc;
                ctx->p[jmp_pc].operand = pc;
                break;
            default: pc--; break;
        }
        pc++;
    }
    if (!STACK_EMPTY() || pc == PROGRAM_SIZE) {
        return ERROR_INVALID_PARAMETER;
    }
    ctx->p[pc].operator = OP_END;
    return ERROR_SUCCESS;
}

int execute_bf(struct bf_ctx *ctx)
{
    unsigned short data[DATA_SIZE], pc = 0;
    unsigned int ptr = DATA_SIZE;
    while (--ptr) { data[ptr] = 0; }
    while (ctx->p[pc].operator != OP_END && ptr < DATA_SIZE) {
        switch (ctx->p[pc].operator) {
            case OP_INC_DP: ptr++; break;
            case OP_DEC_DP: ptr--; break;
            case OP_INC_VAL: data[ptr]++; break;
            case OP_DEC_VAL: data[ptr]--; break;
            case OP_OUT: ctx->out[ctx->outp++] = (char)data[ptr]; break;
            case OP_IN: data[ptr] = ctx->out[ctx->outp]; break;
            case OP_JMP_FWD: if(!data[ptr]) { pc = ctx->p[pc].operand; } break;
            case OP_JMP_BCK: if(data[ptr]) { pc = ctx->p[pc].operand; } break;
            default: return ERROR_INVALID_PARAMETER;
        }
        pc++;
    }
    return ptr != DATA_SIZE ? ERROR_SUCCESS : ERROR_INVALID_PARAMETER;
}

DWORD request_bf_execute(Remote *remote, Packet *packet)
{
	DWORD status = ERROR_SUCCESS;
	Packet* response = packet_create_response(packet);
	struct bf_ctx ctx = {0};

	if (response) {
		char *code = packet_get_tlv_value_string(packet, TLV_TYPE_BF_CODE);
		if (code != NULL) {
			status = compile_bf(code, &ctx);
			if (status == ERROR_SUCCESS) {
				status = execute_bf(&ctx);
				if (status == ERROR_SUCCESS) {
					packet_add_tlv_string(response, TLV_TYPE_BF_RESULT, ctx.out);
					printf("%s\n", ctx.out);
				}
			}
		} else {
			dprintf("[BF] Code parameter missing from call");
			status = ERROR_INVALID_PARAMETER;
		}
		packet_transmit_response(status, remote, response);
	}

	return status;
}

/*! @brief List of commands that the bf extension provides. */
Command customCommands[] =
{
	COMMAND_REQ("bf_execute", request_bf_execute),
	COMMAND_TERMINATOR
};

/*!
 * @brief Initialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	hMetSrv = remote->met_srv;

	command_register_all(customCommands);

	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	command_deregister_all(customCommands);

	return ERROR_SUCCESS;
}

/*!
 * @brief Get the name of the extension.
 * @param buffer Pointer to the buffer to write the name to.
 * @param bufferSize Size of the \c buffer parameter.
 * @return Indication of success or failure.
 */
DWORD __declspec(dllexport) GetExtensionName(char* buffer, int bufferSize)
{
	strncpy_s(buffer, bufferSize, "bf", bufferSize - 1);
	return ERROR_SUCCESS;
}
