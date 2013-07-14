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

;-------------------------------------- vbs.asm ----------------------------------------;
; last changed 13:00 04-9-2007 by anvie
;
;
.code

; module for detect malicious instruction in vbs/bat/js (plain script) command

align 16

ProbePlain proc uses esi image:DWORD,isize:DWORD
	
	LOCAL 	len:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	_PP
	
	; read for 20 byte first
	mov 	edx,isize
	mov 	eax,20
	mov 	len,eax
	cmp 	edx,eax
	ja 		@F
		m2m 	len,isize
	@@:
	
	mov 	esi,image
	mov 	eax,len
	inc 	eax
	scall 	TrimZeroByte,esi,eax
	mov 	esi,eax
	
	push 	esi
	
	strlen 	esi
	mov 	len,eax
	xor 	ecx,ecx
	.while ecx<len
		inc 	ecx
		lodsb
		cmp 	al,32
		jb 		@npl
		cmp 	al,126
		ja 		@npl
	.endw
	pop 	esi
	
	vfree 	esi
	SehPop
	return_1
@npl:
	pop 	esi
	
	vfree 	esi
	SehPop
	return_0
	ret
	
	SehTrap 	_PP
IFNDEF SERVICE
		ErrorDump	"ProbePlain",offset ProbePlain,offset szEngineAsm
ENDIF
	SehEnd 		_PP
	return_0

ProbePlain endp

align 16

TrimZeroByte proc uses edi esi image:DWORD,isize:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__tzb
	
	mov 	eax,isize
	add 	eax,04h
	valloc 	eax
	.if 	eax
		mov 	edi,eax
		mov 	esi,image
		xor 	ecx,ecx
		
		push 	edi
		
		.while ecx<isize
			
			lodsb
			cmp 	al,0
			je 		@F
				cmp 	al,13
				je 	@F
					cmp 	al,10
					je 	@F
						cmp 	al,0ffh
						je 	@F
							cmp		al,0feh
							je 	@F
								cmp 	al,20h
								je 	@F
									cmp 	al,0b7h
									je 	@F
										cmp 	al,0e7h
										je 	@F
											cmp 	al,0B1h
											je 	@F
												cmp 	al,0A9h
												je 	@F
													stosb
			@@:
			
			inc 	ecx
		.endw
		
		pop 	eax
		SehPop
		ret
	.else
IFNDEF SERVICE
		invoke 	AppendLogConsole,reparg("Cannot allocate memory for trimzero")
ENDIF
	.endif
	
	; ------- seh trapper ------- ;
	SehTrap 	__tzb
IFNDEF SERVICE
		ErrorDump	"TrimZeroByte",offset TrimZeroByte,offset szEngineAsm
ENDIF
	SehEnd 		__tzb
	
	return_0
	ret

TrimZeroByte endp

align 16

SearchStrI proc uses edi esi ebx image:DWORD,isize:DWORD,vdb:DWORD
	
	LOCAL 	len:DWORD
	
	; ------- seh installation ------- ;
	SehBegin	__ssi
	
	strlen 	image
	test 	eax,eax
	jz 		@ndtc2
	mov 	len,eax
	mov 	edx,vdb
	
	push 	edx
	mov 	eax,[edx.PLAINCODE].lpszPlain
	mov 	ecx,[edx.PLAINCODE].Len
	invoke 	BMBinSearch,0,image,len,eax,ecx
	js 		@ndtc
	pop 	edx
	lea 	eax,[edx.PLAINCODE].szthName
	SehPop
	ret
	
@ndtc:
	add 	esp,4
@ndtc2:
	SehTrap 	__ssi
		ErrorDump	"SearchStrI",offset SearchStrI,offset szEngineAsm
	SehEnd 		__ssi
	sub 	eax,eax
	ret

SearchStrI endp

align 16

ScanPlainImage proc uses edi esi  image:DWORD,isize:DWORD
	
	LOCAL 	newsize:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__spi
	
	invoke 	ProbePlain,image,isize
	test 	eax,eax
	jnz 	@F
		SehPop
		ret
	@@:
	
	invoke 	TrimZeroByte,image,isize
	test 	eax,eax
	jnz 	@F
		SehPop
		ret
	@@:
	
	mov 	esi,eax
	
	strlen 	esi
	test 	eax,eax
	jz 		@get
	mov 	newsize,eax
	
	lea 	edi,VdbPlain
	@@:
		invoke 	SearchStrI,esi,newsize,edi
		test 	eax,eax
		jnz 	@get
		add 	edi,sizeof PLAINCODE
		cmp 	dword ptr [edi],0
	jne 	@B
	
	align 4
	 
@get:
	push 	eax
	
	vfree 	esi
	
	pop 	eax
	
	SehTrap 	__spi
		ErrorDump 	"ScanPlainImage",offset ScanPlainImage,offset szEngineAsm
	SehEnd 		__spi


	ret

ScanPlainImage endp

