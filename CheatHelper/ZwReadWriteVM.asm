.code

ZwWriteVM proc
	mov r10, rcx
	mov eax, 3Ah
	syscall
	ret
ZwWriteVM endp

ZwReadVM proc
	mov r10, rcx
	mov eax, 3Fh
	syscall
	ret
ZwReadVM endp

end