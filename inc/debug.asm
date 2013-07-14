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


; ------- debug.asm ------- ;
; stuff for debugging


.code
; ------- ONLY FOR DEBUGGING ------- ; 			; --------------------[ -= LOG STUFF =- ]
IFDEF 	DEBUG

InitLog 	proc
	
	invoke 	FileExist,ADDR szFileLog
	.if 	eax
		invoke 	DeleteFile,ADDR szFileLog
	.endif
	invoke 	CreateFile,ADDR szFileLog,
			GENERIC_WRITE,
			FILE_SHARE_WRITE,
			0,
			CREATE_NEW,
			FILE_ATTRIBUTE_NORMAL,
			0
	.if 	eax == -1
		return_0
	.endif
	
	mov 	hFileLog,eax
	ret

InitLog endp

align 4

Log 	proc lpszLog:DWORD
	LOCAL 	lbrw:DWORD
	
	push ecx
	push edx
	push eax
	.if 	hFileLog
		invoke 	SetFilePointer,hFileLog,0,0,FILE_END
		
		strlen lpszLog
		
;		mov 	edx,lpszLog
;		@@:
;			mov al,[edx]
;			inc edx
;			test al,al
;			jne @B
;		dec edx
;		sub edx,lpszLog
;		mov eax,edx
		lea 	edx,lbrw
		invoke 	WriteFile,hFileLog,lpszLog,eax,edx,0 
	.endif
	pop eax
	pop edx
	pop ecx
	ret

Log endp

CloseLog 	proc
	
	SehBegin 	_cg

	.if 	hFileLog
		invoke 	CloseHandle,hFileLog
		mov 	hFileLog,0
	.endif
	
	SehTrap 	_cg
	SehEnd 		_cg
	
	ret

CloseLog endp

ENDIF	

mLog 	MACRO arg
	LOCAL 	nustr
IFDEF 	DEBUG
	quot  SUBSTR <arg>,1,1
	; ------- Save reg ------- ;
	push 	eax
	IFIDN	quot,<">
	.data
		nustr 	db arg,13,10,0
	.code
	lea 	eax,nustr
	push 	eax
	ELSE
	push 	arg
	ENDIF
	call 	Log
	; ------- Make Crlf ------- ;
	IFDIF	quot,<">
	push 	offset szCrlf
	call 	Log
	ENDIF
	; ------- Restore used reg ------- ;
	pop 	eax
ENDIF
endm

			; --------------------[ -= END OF LOG STUFF =- ]

; ------- FOR BUG HUNTER ------- ; 			; --------------------[ -= ERROR LOG STUFF =- ]
IFDEF 	ERRORLOG

InitErrorLog 	proc
	pushad
	.if 	!hFileErrorLog
		invoke 	FileExist,ADDR szFileErrorLog
		.if 	eax
			mov 	eax,OPEN_EXISTING
		.else
			mov 	eax,CREATE_NEW
		.endif
		invoke 	CreateFile,ADDR szFileErrorLog,
				GENERIC_WRITE,
				FILE_SHARE_WRITE,
				0,
				eax,
				FILE_ATTRIBUTE_NORMAL,
				0
		.if 	eax == -1
			popad
			return_0
		.endif
		mov 	hFileErrorLog,eax
		
		invoke 	GetFileSize,eax,0
		mov 	ErrorOccured,eax
	.endif
	popad
	ret

InitErrorLog endp

WriteError 	proc lpszError:DWORD
	LOCAL 	lBuff[1024]:BYTE
	LOCAL 	lbrw:DWORD
	pushad
	
	call 	InitErrorLog
	.if 	hFileErrorLog
		; ------- Check for first error ------- ;
		.if 	!ErrorOccured
			mov 	ErrorOccured,1
			invoke 	MyZeroMemory,ADDR lBuff,1024
			; ------- Create Message for user who looking at error log file ------- ;
			
			lea eax,szErrorMsgLogFile
			strlen eax
			
			lea 	edx,lbrw
			invoke 	WriteFile,hFileErrorLog,ADDR szErrorMsgLogFile,eax,edx,0
			
			; ------- put user system version ------- ;
			analloc sizeof OSVERSIONINFOEX
			mov 	esi,eax
			test 	esi,esi
			jz 		@nosv
				analloc 512
				mov 	edi,eax
				test 	edi,edi
				jz 		@nobf
					invoke 	MyZeroMemory,esi,sizeof OSVERSIONINFOEX
					assume 	esi:ptr OSVERSIONINFOEX
					mov 	[esi].dwOSVersionInfoSize,sizeof OSVERSIONINFOEX  
					invoke 	GetVersionEx,esi
					
						movzx 	eax,word ptr [esi].wServicePackMinor
					push 	eax
						movzx 	eax, word ptr [esi].wServicePackMajor
					push 	eax
					push 	[esi].dwBuildNumber ; build
					push 	[esi].dwMinorVersion ; 1
					push 	[esi].dwMajorVersion ; 5
						lea 	eax,szWindowsVersionF
					push 	eax
					push 	edi
					call 	wsprintf
					add 	esp,4*7
					
					strlen edi
					
					lea 	ecx,lbrw
					invoke 	WriteFile,hFileErrorLog,edi,eax,ecx,0
					anfree 	edi
			@nobf:
				anfree 	esi
			@nosv:
			
			assume 	esi:nothing
			
			; ------- Put ansav version ------- ;
							 
			push 	dwRDYear
			push 	dwRDMonth
			push 	dwRDDay
			push 	VerRevision
			push 	VerMinor
			push 	VerMajor
				lea 	eax,szErrorLogAnsavVersionF
			push 	eax
				lea 	eax,lBuff
			push 	eax
			call 	wsprintf
			add 	esp,4*8
							 
			lea eax,lBuff
			strlen eax
			
			lea 	edx,lbrw
			invoke 	WriteFile,hFileErrorLog,ADDR lBuff,eax,edx,0
			
			strlen offset szSparator
			
			lea 	edx,lbrw
			invoke 	WriteFile,hFileErrorLog,ADDR szSparator,eax,edx,0
		.endif
		
		invoke 	SetFilePointer,hFileErrorLog,0,0,FILE_END
		
		strlen lpszError
		
		xchg 	eax,ecx
		invoke 	WriteFile,hFileErrorLog,lpszError,ecx,ADDR lbrw,0
		invoke 	WriteFile,hFileErrorLog,ADDR szCrlf,2,ADDR lbrw,0
	.endif
	
	
	popad

	ret
WriteError endp


ErrorLog 	proc lpszLog:DWORD
	LOCAL 	lbrw:DWORD
	LOCAL 	lBuff[1024]:BYTE
	LOCAL 	stime:SYSTEMTIME
	pushad
	call 	InitErrorLog
	.if 	hFileErrorLog
	
		; ------- Check for first error ------- ;
		.if 	!ErrorOccured
			mov 	ErrorOccured,1
			invoke 	MyZeroMemory,ADDR lBuff,1024
			; ------- Create Message for user who looking at error log file ------- ;
			
			lea eax,szErrorMsgLogFile
			strlen eax
			
			lea 	edx,lbrw
			invoke 	WriteFile,hFileErrorLog,ADDR szErrorMsgLogFile,eax,edx,0
			
			; ------- put user system version ------- ;
			analloc sizeof OSVERSIONINFOEX
			mov 	esi,eax
			test 	esi,esi
			jz 		@nosv
				analloc 512
				mov 	edi,eax
				test 	edi,edi
				jz 		@nobf
					invoke 	MyZeroMemory,esi,sizeof OSVERSIONINFOEX
					assume 	esi:ptr OSVERSIONINFOEX
					mov 	[esi].dwOSVersionInfoSize,sizeof OSVERSIONINFOEX  
					invoke 	GetVersionEx,esi
					
						movzx 	eax,word ptr [esi].wServicePackMinor
					push 	eax
						movzx 	eax, word ptr [esi].wServicePackMajor
					push 	eax
					push 	[esi].dwBuildNumber ; build
					push 	[esi].dwMinorVersion ; 1
					push 	[esi].dwMajorVersion ; 5
						lea 	eax,szWindowsVersionF
					push 	eax
					push 	edi
					call 	wsprintf
					add 	esp,4*7
					
					strlen edi
					
					lea 	ecx,lbrw
					invoke 	WriteFile,hFileErrorLog,edi,eax,ecx,0
					anfree 	edi
			@nobf:
				anfree 	esi
			@nosv:
			
			assume 	esi:nothing
			
			; ------- Put ansav version ------- ;
							 
			push 	dwRDYear
			push 	dwRDMonth
			push 	dwRDDay
			push 	VerRevision
			push 	VerMinor
			push 	VerMajor
				lea 	eax,szErrorLogAnsavVersionF
			push 	eax
				lea 	eax,lBuff
			push 	eax
			call 	wsprintf
			add 	esp,4*8
			
			
			lea eax,lBuff
			strlen eax
			
			lea 	edx,lbrw
			invoke 	WriteFile,hFileErrorLog,ADDR lBuff,eax,edx,0
			
			strlen offset szSparator
			
			lea 	edx,lbrw
			invoke 	WriteFile,hFileErrorLog,ADDR szSparator,eax,edx,0
		.endif
		
		invoke 	SetFilePointer,hFileErrorLog,0,0,FILE_END
		
		; ------- format to error ------- ;
		invoke 	MyZeroMemory,ADDR lBuff,1024
		invoke 	MyZeroMemory,ADDR stime,sizeof SYSTEMTIME
		invoke 	GetLocalTime,ADDR stime
		
		invoke 	GetLastError			   ; -------  time x:x:x code : x, desc ------- ;
		push 	lpszLog
		push 	eax
		movzx 	eax,[stime.wSecond]
		push 	eax
		movzx 	eax,[stime.wMinute]
		push 	eax
		movzx 	eax,[stime.wHour]
		push 	eax
		lea 	eax,szErrorLogF
		push 	eax
		lea 	eax,lBuff
		push 	eax
		call 	wsprintf
		add 	esp,7*4
		
		
		lea 	edi,lBuff
		
		strlen edi
		
		mov 	word ptr [edi+eax],0a0dh
		add 	eax,2
		lea 	edx,lbrw
		invoke 	WriteFile,hFileErrorLog,ADDR lBuff,eax,edx,0
	.endif
	popad
	ret

ErrorLog endp

CloseErrorLog 	proc

	; ------- seh installation ------- ;
	SehBegin 	__cel

	.if 	hFileErrorLog
		invoke 	CloseHandle,hFileErrorLog
		mov 	hFileErrorLog,0
	.endif

	.if 	!ErrorOccured
		invoke 	DeleteFile,ADDR szFileErrorLog
	.endif
	
	; ------- seh trapper ------- ;
	SehTrap 	__cel
		ErrorDump 	"CloseErrorLog",offset CloseErrorLog,"debug.asm"
	SehEnd 		__cel
	
	ret

CloseErrorLog endp

ENDIF	

			; --------------------[ -= END OF ERROR LOG STUFF =- ]















