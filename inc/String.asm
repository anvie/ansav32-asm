;------------------------------------------------------------------------------;
;
;   ANSAV An's Antivirus
;   Copyright (C) 2007-2008 Muqorrobien Ma'rufi a.k.a 4NV|e
;
;   
;   Muqorrobien Ma'rufi a.k.a 4NV|e
;   anvie_2194 @ yahoo.com
;   http://www.ansav.com
;   PP. Miftahul Huda Blok C Siwatu Wonosobo 56352 Jawa Tengah Indonesia
;   
;
;------------------------------------------------------------------------------;


; ------- String.asm ------- ;

.code ; ------- String ------- ;

include 	inc\atodw.asm

; ------- Trims all space char ------- ;
KillSpace proc uses esi edi lpString:DWORD,cchMax:DWORD

	LOCAL 	retv:DWORD

	mov 	retv,0

	mov 	esi,lpString
	cmp 	byte ptr [esi],0
	jnz 	@F
	return_0
	@@:

	; ------- Alloc mem first ------- ;
	analloc 	cchMax
	.if 	eax
		mov 	edi,eax
		mov 	esi,lpString
		
		push 	edi
		push 	esi
		
		strlen lpString
		
		xchg 	eax,ecx
		@lp:
			mov 	al,[esi]
			cmp 	al,' '
			je 		@F
			mov 	[edi],al
			inc 	edi
			@@:
			inc 	esi
		Loop	@lp
		
		pop		esi
		pop 	edi
		
		strlen edi
		
		.if 	eax
			mov 	retv,eax	; return value = new length
			
			; -------  copy it to IN OUT buffer ------- ;
			inc		eax
			invoke 	lstrcpyn,lpString,edi,eax
			
		.endif
		
		anfree 	edi
	.endif
	
	mov 	eax,retv
	ret
KillSpace endp

align 16

; ------- Specified seek & replace char ------- ;
ReplaceChar proc uses esi edi lpString:DWORD,szCharToReplace:BYTE,szNewChar:BYTE,cchMax:DWORD

	LOCAL 	oldlen:DWORD
	LOCAL 	retv:DWORD
	
	mov 	retv,0

	; ------- Alloc mem first ------- ;
	analloc 	cchMax
	.if 	eax
		mov 	edi,eax
		mov 	esi,lpString
		
		push 	edi
		push 	esi
		
		cmp 	byte ptr [esi],0
		je 		@endl
		
		strlen esi
		
		mov 	oldlen,eax
		xchg 	eax,ecx
		@lp:
			mov 	al,byte ptr [esi]
			cmp 	al,szCharToReplace
			.if 	zero?
				mov 	al,szNewChar
			.endif
			mov 	byte ptr [edi],al
			inc 	edi
			inc 	esi
		Loop	@lp
		
		pop		esi
		pop 	edi
		
			m2m 	retv,oldlen	; return value = new length
			
			; -------  copy it to IN OUT buffer ------- ;
			invoke 	MyCopyMem,lpString,edi,oldlen
@endl:
		anfree 	edi
	.endif
	
	mov 	eax,retv
	ret
ReplaceChar endp

; ------- Get longer space in the strings ------- ;
GetSpaceOnly proc uses esi lpBuffer:DWORD,lpString:DWORD,cchMax:DWORD
	
	LOCAL 	sState,eState:DWORD
	LOCAL 	lCount,len:DWORD
	LOCAL 	retv:DWORD
	
	mov 	retv,0
	
	strlen lpString
	
	mov 	ecx,eax
	mov 	len,eax
	
	mov 	esi,lpString
	
	@lp:
		cmp 	byte ptr [esi],' '
		jne 	@nx
			mov 	sState,esi
			
			mov 	lCount,0
			; ------- Check long ------- ;
			@lp2:
				cmp 	byte ptr [esi],' '
				jne 	@ends
				inc		lCount
				inc 	esi
			loop 	@lp2
			@ends:
			
			cmp 	lCount,15
			jb 		@lp
			
			; set end state
			mov 	eState,esi
			jmp 	@getout
			
		@nx:
		inc 	esi
	loop 	@lp
	
	jmp 	@endl
@getout:
	
	; ------- Long Space Found ------- ;
	invoke 	MyZeroMemory,lpBuffer,cchMax
	mov 	ecx,eState
	sub 	ecx,sState
	invoke 	lstrcpyn,lpBuffer,sState,ecx
	mov 	retv,1
@endl:
	mov 	eax,retv
	ret

GetSpaceOnly endp


