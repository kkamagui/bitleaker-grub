/* callwrap.S - wrapper for x86_64 efi calls */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2006,2007,2009  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <grub/symbol.h>

/*
 * x86_64 uses registry to pass parameters. Unfortunately, gcc and efi use
 * different call conversion, so we need to do some conversion.
 *
 * gcc:
 *   %rdi,  %rsi,  %rdx,  %rcx, %r8, %r9, 8(%rsp), 16(%rsp), ...
 *
 * efi:
 *   %rcx,  %rdx,  %r8,  %r9,  32(%rsp), 40(%rsp), 48(%rsp), ...
 *
 */

        .file   "callunwrap.S"
        .text

/* Macros for unwrap UEFI function calls */
.macro SAVE_CONTEXT
	// get 5th argument to rax
	mov 80(%rsp), %rax
	push %rbx
	push %rcx
	push %rdx
	push %rsi
	push %rdi
	push %rbp
	push %r8
	push %r9
	push %r10
	push %r11
	push %r12
	push %r13
	push %r14
	push %r15
.endm

.macro RESTORE_CONTEXT
	pop %r15
	pop %r14
	pop %r13
	pop %r12
	pop %r11
	pop %r10
	pop %r9
	pop %r8
	pop %rbp
	pop %rdi
	pop %rsi
	pop %rdx
	pop %rcx
	pop %rbx
.endm

FUNCTION(efi_unwrap_2_get_capability)
	subq $40, %rsp
	SAVE_CONTEXT
	mov %rcx, %rdi
	mov %rdx, %rsi

	call hook_get_capability
	RESTORE_CONTEXT
	addq $40, %rsp
	ret

FUNCTION(efi_unwrap_5_get_event_log)
	subq $40, %rsp
	SAVE_CONTEXT
	mov %rcx, %rdi
	mov %rdx, %rsi
	mov %r8, %rdx
	mov %r9, %rcx
	mov %rax, %r8

	call hook_get_event_log
	RESTORE_CONTEXT
	addq $40, %rsp
	ret

FUNCTION(efi_unwrap_5_hash_log_extend_event)
	subq $40, %rsp
	SAVE_CONTEXT
	mov %rcx, %rdi
	mov %rdx, %rsi
	mov %r8, %rdx
	mov %r9, %rcx
	mov %rax, %r8

	call hook_hash_log_extend_event
	RESTORE_CONTEXT
	addq $40, %rsp
	ret

FUNCTION(efi_unwrap_5_submit_command)
	subq $40, %rsp
	SAVE_CONTEXT
	mov %rcx, %rdi
	mov %rdx, %rsi
	mov %r8, %rdx
	mov %r9, %rcx
	mov %rax, %r8

	call hook_submit_command
	RESTORE_CONTEXT
	addq $40, %rsp
	ret