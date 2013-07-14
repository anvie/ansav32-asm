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

; ------- ConsoleLog.asm ------- ;
.data
	szTxtConsoleSparator	db "-------------------------------------",0
	szTxtConsoleTitle		db " ANSAV +E ADVANCED LOG SYSTEM",0
	szTxtConsoleVersionF	db " Version %d.%d.%d",0
	szTxtConsoleLastUpdF	db " Last update %d.%d.%d",0
.code

InitConsoleLog proc uses esi
	
	LOCAL 	lBuff[512+1]:BYTE
	
	; ------- seh installation ------- ;
	SehBegin 	__icl
	
	mov 	esi,AppendLogConsole
	
	invoke 	MyZeroMemory,ADDR lBuff,512
	invoke 	SetWindowText,hTxtConsoleLog,ADDR szTxtConsoleSparator
	scall 	esi,offset szTxtConsoleTitle
	
		push 	VerRevision
		push 	VerMinor
		push 	VerMajor
	lea 	eax,szTxtConsoleVersionF
		push 	eax
	lea 	eax,lBuff
		push 	eax
	call 	wsprintf
	add 	esp,4*5
	
	lea 	eax,lBuff
	scall 	esi,eax
	
		push 	dwRDYear
		push 	dwRDMonth
		push 	dwRDDay
	lea 	eax,szTxtConsoleLastUpdF
		push 	eax
	lea 	eax,lBuff
		push 	eax
	call 	wsprintf
	add 	esp,4*5
	
	lea 	eax,lBuff
	scall 	esi,eax
	scall 	esi,offset szTxtConsoleSparator
	
	
	lea 	eax,szScanLogReady
	push 	eax
	call 	AppendLogConsole

	; ------- seh trapper ------- ;
	SehTrap 	__icl
		ErrorDump	"InitConsoleLog",offset InitConsoleLog,"consolelog.asm"
	SehEnd 		__icl
	
	ret

InitConsoleLog endp

align 16

AppendLogConsole proc uses edi esi ebx ecx edx lpszText:DWORD
	
	LOCAL 	lBuffer:DWORD
	LOCAL 	len:DWORD
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	
	.if 	ScanLogReady
		
		
		invoke 	MyZeroMemory,ADDR lBuff,MAX_PATH
		
		; ------- get last text in ctrl ------- ;
		invoke 	GetWindowTextLength,hTxtConsoleLog
		.if 	eax
			
			.if 	eax > 50000
				push 	eax
				call 	InitConsoleLog
				pop 	eax
			.endif
			
			push 	eax
			
			strlen lpszText
			
			inc 	eax
			add 	eax,2
			pop 	ecx
			add 	ecx,eax
			mov 	len,ecx
			valloc 	ecx
			.if 	eax
				mov 	lBuffer,eax
				
				invoke GetWindowText,hTxtConsoleLog,lBuffer,len
				
				; ------- append it ------- ;
				invoke 	lstrcat,lBuffer,ADDR szCrlf
				invoke 	lstrcat,lBuffer,lpszText
				
				; ------- set it back to edit window ------- ;
				invoke 	SetWindowText,hTxtConsoleLog,lBuffer
				
				invoke 	GetWindowTextLength,hTxtConsoleLog
				invoke 	SendMessage,hTxtConsoleLog,EM_LINESCROLL,0,eax
				
				invoke 	UpdateWindow,hConsoleLogDlg
				
				invoke 	Sleep,5
				vfree 	lBuffer
			.endif
			
			
		.endif
		
	.endif
	ret

AppendLogConsole endp

align 16

TxtConsoleLog proc	hCtl:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	LOCAL 	hDC:DWORD
	mov 	eax,uMsg
	.if 	eax	 == WM_CHAR
		
		mov 	[wParam],0
		
	.endif
	invoke 	CallWindowProc,lpTxtConsoleLog,hCtl,uMsg,wParam,lParam
	ret

TxtConsoleLog endp

align 16


ConsoleLogDlgProc proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	LOCAL 	lbrw:DWORD
	
	mov 	eax,uMsg
	.if 	eax == WM_INITDIALOG
	
		m2m 	hConsoleLogDlg,hWin
		
		.if 	TimeForBlind
			invoke 	MakeRandomString,ADDR szRandomString,10
			invoke 	SetWindowText,hWin,ADDR szRandomString 
		.endif
		
		invoke 	GetDlgItem,hWin,101
		mov 	hTxtConsoleLog,eax
		invoke 	SetWindowLong,eax,GWL_WNDPROC,ADDR TxtConsoleLog
		mov 	lpTxtConsoleLog,eax
		
		; ------- win state ------- ;
		invoke 	GetSystemMetrics,SM_CXFULLSCREEN
		sub 	eax,365
		push 	eax
		invoke 	GetSystemMetrics,SM_CYFULLSCREEN
		mov 	ecx,eax
		sub 	ecx,270
		pop 	eax
		invoke 	SetWindowPos,hWin,HWND_TOP,eax,ecx,0,0,SWP_NOSIZE
		
		mov 	ScanLogReady,1
		call 	InitConsoleLog
		invoke 	MakeFont,11,4,200,0,reparg("Terminal")
		mov 	hTerminalFont,eax
		
		invoke 	SendMessage,hTxtConsoleLog,WM_SETFONT,hTerminalFont,0
		invoke 	SetFocus,hWin
		invoke 	GetWindowTextLength,hTxtConsoleLog
		invoke 	SendMessage,hTxtConsoleLog,EM_SETSEL,eax,eax
		
		invoke 	CreateSolidBrush,0
		mov 	ClrBrushBlack2,eax
	.elseif 	eax == WM_CTLCOLOREDIT
		invoke 	SetBkMode,[wParam],TRANSPARENT
		invoke 	SetTextColor,[wParam],0000FF00h
		mov 	eax,ClrBrushBlack2
		ret
	.elseif 	eax == WM_COMMAND
		mov 	eax,wParam
		and 	eax,0FFFFh
		.if 	eax == 1003 	; <-- Close ;
			jmp		@close 	
		.elseif 	eax == 1002 	; <-- Clear ;
			call 	InitConsoleLog
		.elseif 	eax == 1004 	; <-- Copy ;
			invoke 	GetWindowTextLength,hTxtConsoleLog
			push 	eax
			invoke 	SendMessage,hTxtConsoleLog,EM_SETSEL,0,eax
			invoke 	SendMessage,hTxtConsoleLog,WM_COPY,0,0
			pop 	eax
			invoke 	SendMessage,hTxtConsoleLog,EM_SETSEL,eax,eax
		.elseif 	eax == 1001 	; <-- View in notepad ;
			push edi
			push esi
			push ebx
			analloc 	MAX_PATH+1
			.if 	eax
				mov 	esi,eax
				invoke 	lstrcpy,esi,ADDR szTempDir
				invoke  TruePath,esi
				invoke  lstrcat,esi,ADDR szTempScanLog
				invoke 	FileExist,esi
				.if 	eax
					invoke 	DeleteFile,esi
				.endif
				invoke 	CreateFile,esi,GENERIC_WRITE,FILE_SHARE_WRITE,0,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0
				.if 	eax != -1
					mov 	ebx,eax
					
					invoke 	GetWindowTextLength,hTxtConsoleLog
					.if 	eax
						inc 	eax
						push 	eax
						valloc 	eax
						pop 	ecx
						.if 	eax
							mov 	edi,eax
							push 	ecx
							invoke 	GetWindowText,hTxtConsoleLog,edi,ecx
							pop 	ecx
							.if 	byte ptr [edi]
								
								invoke 	WriteFile,ebx,edi,ecx,ADDR lbrw,0
								
							.endif
							
							vfree 	edi
						.endif
					.endif
					
					invoke 	CloseHandle,ebx
					invoke 	ShellExecute,hWin,ADDR szOpen,esi,0,ADDR szTempDir,SW_SHOWMAXIMIZED
				.endif
				
				anfree 	esi
			.endif
			pop ebx
			pop esi
			pop edi
		.elseif 	eax == 1005 	; <-- always on top ;
			invoke 	TopNoTop,hWin,eax
		.endif
	.elseif 	eax == WM_CLOSE
	@close:
		mov 	ScanLogReady,0
		invoke 	DeleteObject,ClrBrushBlack2
		invoke 	DeleteObject,hTerminalFont
		invoke  DestroyWindow,hWin
	.endif
	
	xor 	eax,eax
	ret

ConsoleLogDlgProc endp

align 16

StartConsoleLogDlgProc proc
	
	invoke 	CreateDialogParam,hInstance,IDD_CONSOLELOG,hMainWnd,ADDR ConsoleLogDlgProc,0
	
	ret

StartConsoleLogDlgProc endp

