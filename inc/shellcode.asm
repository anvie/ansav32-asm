;------------------------------------------------------------------------------;
;
;   ANSAV An's Antivirus
;   Copyright (C) 2007-2008 Muqorrobien Ma'rufi a.k.a 4NV|e
;
;   Muqorrobien Ma'rufi a.k.a 4NV|e
;   anvie_2194 @ yahoo.com
;   http://www.ansav.com
;   PP. Miftahul Huda Blok C Siwatu Wonosobo 56352 Jawa Tengah Indonesia
;   
;
;------------------------------------------------------------------------------;

;-------------------------------------- shellcode.asm ----------------------------------------;

.code


SSelfDelete::

	mov 	eax,12345678h
	push 	5000
	call 	eax

	call 	@@DeltaSSD
@@DeltaSSD:
	pop 	ebp
	sub 	ebp,offset @@DeltaSSD-offset SSelfDelete
	
@@SetFileAttributeSSD equ $ - offset SSelfDelete + 1
	mov 	eax,12345678h
	push 	FILE_ATTRIBUTE_NORMAL
	lea 	esi,[ebp+SszAnsavPath]
	push 	esi
	call 	eax

@@DeleteFileSSD equ $ - offset SSelfDelete + 1
	mov 	eax,12345678h
	push 	esi
	call 	eax

	cld
	mov 	edi,esi
	or 		ecx,0FFFFFFFFh
	xor 	al,al
	repnz	scasb
	not 	ecx
	dec 	ecx
	mov 	edi,esi
	@@:
		cmp 	byte ptr [edi+ecx],05Ch
		je 	@F
	loop 	@B
	@@:
	mov 	byte ptr [edi+ecx],0

@@RemoveDirectorySSD equ $ - offset SSelfDelete + 1
	mov 	eax,12345678h
	push 	esi
	call 	eax
	
@@MessageBoxSSD equ $ - offset SSelfDelete + 1
	mov 	esi,12345678h
	push 	MB_ICONINFORMATION
	lea 	edi,[ebp+SszAnsavPath]
	add 	edi,MAX_PATH
	inc 	edi
	push 	edi
	cld
	xor 	al,al
	or 		ecx,0FFFFFFFFh
	repnz 	scasb
	push 	edi
	push 	0
	call 	esi
	
@@ExitThreadSSD equ $ - offset SSelfDelete + 1
	mov 	eax,12345678h
	push 	0
	call 	eax
	retn
; ------- DATA ------- ;
SszAnsavPath	equ $ - offset SSelfDelete 
	db MAX_PATH+1 dup(0)
	db "ANSAV Uninstaller",0
	db "Uninstall completed.",0,0

SSelfDeleteSize 	equ $ - offset SSelfDelete
;-------------------------------------endofSSelfDelete-----------------------------------------;










