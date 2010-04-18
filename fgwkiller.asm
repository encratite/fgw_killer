include common.inc

include kernel32.inc
include user32.inc

.data?
	hook_handle dd ?

.code

keyboard_hook proc nCode:dword, wParam:dword, lParam:dword
	mov eax, [esp + 3 * 4]
	assume eax: ptr KBDLLHOOKSTRUCT
	cmp [eax].vkCode, VK_PAUSE
	jnz next_hook
	test [eax].flags, LLKHF_UP
	jnz next_hook
	test [eax].flags, LLKHF_ALTDOWN
	jz next_hook
	call GetForegroundWindow
	test eax, eax
	jz next_hook
	sub esp, 4
	invoke GetWindowThreadProcessId, eax, esp
	invoke OpenProcess, PROCESS_TERMINATE, FALSE, [esp]
	add esp, 4
	test eax, eax
	jz next_hook
	invoke TerminateProcess, eax, 0
next_hook:
	invoke CallNextHookEx, keyboard_hook, [esp + 4 + 2 * 4], [esp + 2 * 4 + 4], [esp + 3 * 4]
	ret
keyboard_hook endp

start:
	invoke GetModuleHandleA, 0
	invoke SetWindowsHookExA, WH_KEYBOARD_LL, addr keyboard_hook, eax, 0
	test eax, eax
	jz exit
	mov hook_handle, eax
	sub esp, 4
	lea eax, [esp + 3 * 4]
	invoke GetMessageA, eax, 0, 0, 0
	invoke UnhookWindowsHookEx, hook_handle
exit:
	invoke Exitprocess, 0
end start