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

; ------- ViewResultDlg.asm ------- ;


IDC_EDIT_VIEWRES 	equ 1001
IDC_VIEWRES_CLOSE 	equ 1002
IDC_VIEWRES_COPY 	equ 1003
IDC_VIEWRES_NOTEPAD	equ 1005

.data?
	hViewResultDlg 	dd ?
	hTerminalFont	dd ?
	hTxtViewRes		dd ?
	lpTxtViewRes	dd ?
.data
	
	szResultDataF	db 13,10
					db "------------------------------------",13,10
					db "ANSAV Last Scanned Result",13,10
					db "Reported on %d:%d:%d,  %d-%d-%d",13,10
					db "------------------------------------",13,10
					db 13,10
					db "Engine version : %d.%d.%d",13,10
					db "Last update    : %d.%d.%d",13,10
					db 13,10
					db 'Scanning on "%s"',13,10,0
	szSComplete		db 'Scanning completed with the following result:',13,10,0
	szSNotComplete	db 'Scanning not complete, aborted by user',13,10,0
	szScanTimeF		db 13,10
					db "Started at %d:%d:%d and was finished in %d:%d:%d",13,10
					db "Scan process take for :",13,10,0
	szHourF			db " %d hours,",0
	szMinuteF		db " %d minutes,",0
	szSecondsF		db " %d seconds,",0
	szMillscndsF	db " %d milliseconds",13,10,0
	szFollowResultF db 13,10
					db '    File(s) Checked : %d',13,10
					db '    Threat(s) Found : %d',13,10
					db 13,10,0
	szTheseObjDtc	db 'These is detected threat(s) object :',13,10,13,10,0
	szThreatNameF	db '  -> [ DETECTED! ] ',13,10
					db '  -> %s',13,10,13,10,0
	szHeurF			db '  -> [ SUSPECTED! ] ',13,10
					db '  -> Have some virus/worm/trojan characteristics',13,10,13,10,0
	szHeurNameF		db '  -> [ SUSPECTED! ] ',13,10
					db '  -> %s',13,10,13,10,0
	szTheseObjClr	db 'All detected object was cleaned successfully',13,10,0
	szFinalResultF	db 13,10
					db '       Final result : [ %s ]',13,10,0
	szSThreatDetc	db 'Threat(s) detected!!',0
	szSThreatNotdtc	db 'So far so good',0
	szSAborted		db 'Nothing',0
.code

align 16

BuildResult proc uses 	esi ebx
	LOCAL 	hFile,fSize,memptr:DWORD
	LOCAL 	Count,sState,dState:DWORD
	LOCAL 	lBuff[1024+1]:BYTE
	LOCAL 	lBuff2[30+1]:BYTE
	LOCAL 	stime:SYSTEMTIME
	LOCAL 	lvi:LV_ITEM
	LOCAL 	retv,lbrw:DWORD

	; ------- seh installation ------- ;
	SehBegin 	__br
	mov 	esi,MyZeroMemory
	
	lea 	eax,stime
	scall 	esi,eax,sizeof SYSTEMTIME
	lea 	eax,lBuff
	scall 	esi,eax,1024
	lea 	eax,lBuff2
	scall 	esi,eax,30
	lea 	eax,lvi
	scall 	esi,eax,LV_ITEM
	mov 	retv,0
	
	lea 	esi,LastScannedInfo
	assume 	esi:ptr LASTSCANNEDINFO
	
	invoke 	FileExist,ADDR szTempFilePath
	.if 	eax
		invoke 	DeleteFile,ADDR szTempFilePath
		invoke 	Sleep,500
	.endif
	
	invoke 	CreateFile,ADDR szTempFilePath,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ or FILE_SHARE_WRITE,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0
	.if 	eax != -1
		mov 	hFile,eax
		
		lea 	eax,[esi].szLocation
		cmp 	byte ptr [eax],0
		.if 	zero?
			invoke 	SetWindowText,hTxtViewRes,reparg("No information to report.")
			jmp 	@endl2
		.endif
		
		push 	eax
		push 	dwRDYear
		push 	dwRDMonth
		push 	dwRDDay
		push 	VerRevision
		push 	VerMinor
		push	VerMajor
		invoke 	GetLocalTime,ADDR stime
		movzx 	eax,[stime.wYear]
		push 	eax
		movzx 	eax,[stime.wMonth]
		push 	eax
		movzx 	eax,[stime.wDay]
		push 	eax
		movzx 	eax,[stime.wSecond]
		push 	eax
		movzx 	eax,[stime.wMinute]
		push 	eax
		movzx 	eax,[stime.wHour]
		push 	eax
		; -------------- ;
		lea 	eax,szResultDataF
		push 	eax
		lea 	eax,lBuff
		push 	eax
		call 	wsprintf
		add 	esp,4*15	
		
		invoke 	SetFilePointer,hFile,0,0,FILE_BEGIN
		
		lea eax,lBuff
		strlen eax
		
		xchg 	eax,ecx
		lea 	edx,lbrw
		invoke	WriteFile,hFile,ADDR lBuff,ecx,edx,0
		
		; ------- Last scanned path ------- ;
		.if 	LastScannedPath
			
			mov 	edi,LastScannedPath
			; get path count in buffer
			mov 	Count,0
			@lp_getcnt:
				inc 	Count
			NextArray	@lp_getcnt
			; ------- calculate crlf ------- ;
			mov 	eax,2
			mov 	ecx,Count
			mul 	ecx
			add 	eax,LastScannedPathSize
			; ------- allocate secondary buffer ------- ;
			valloc 	eax
			.if 	eax
				mov 	ebx,eax
				mov 	edi,LastScannedPath
				
				push 	ebx
				
				mov 	word ptr [ebx],0a0dh
				add 	ebx,2
				invoke 	lstrcpy,ebx,reparg("Last scanned path :")
				add 	ebx,19
				mov 	dword ptr [ebx],0a0d0a0dh
				add 	ebx,4
				@buildpath:
					
					invoke 	lstrcpyn,ebx,edi,MAX_PATH
					
					strlen ebx
					
					mov 	word ptr [ebx+eax],0a0dh
					add 	ebx,eax
					add 	ebx,2					
					
				NextArray 	@buildpath
				mov 	word ptr [ebx],0a0dh
				pop 	ebx
				
				; ------- write it ------- ;
				strlen ebx
				
				xchg 	eax,ecx
				lea 	edx,lbrw
				invoke 	WriteFile,hFile,ebx,ecx,edx,0
				
				; ------- flush mem ------- ;
				vfree 	ebx
			.else
				mErrorLog 	"Cannot allocate memory secondary buffer for LastScannedPath that needed for build result"
			.endif
			
		.endif
		
		; ------- time ------- ;
		; ------- end scan ------- ;
		movzx 	eax,[TimeEndScan.wSecond]
			push 	eax
		movzx 	eax,[TimeEndScan.wMinute]
			push 	eax
		movzx 	eax,[TimeEndScan.wHour]
			push 	eax
		; ------- begin scan ------- ;
		movzx 	eax,[TimeBeginScan.wSecond]
			push 	eax
		movzx 	eax,[TimeBeginScan.wMinute]
			push	 eax
		movzx 	eax,[TimeBeginScan.wHour]
			push 	eax
		; ------- format ------- ;
		lea 	eax,szScanTimeF
			push 	eax
		; ------- buffer ------- ;
		lea 	eax,lBuff
			push 	eax
		call 	wsprintf
		add 	esp,4*8
		
		push 	esi
		
		mov 	esi,lstrcat
		
		movzx 	eax,[TimeTakeA.wHour]
		xor 	ebx,ebx
		.if 	eax
			invoke 	wsprintf,ADDR lBuff2,ADDR szHourF,eax
			lea 	eax,lBuff
			lea 	edx,lBuff2
			scall 	esi,eax,edx
			inc 	ebx
		.endif
		movzx 	eax,[TimeTakeA.wMinute]
		.if 	eax
			invoke 	wsprintf,ADDR lBuff2,ADDR szMinuteF,eax
			lea 	eax,lBuff
			lea 	edx,lBuff2
			scall 	esi,eax,edx
			inc 	ebx
		.endif
		movzx 	eax,[TimeTakeA.wSecond]
		.if 	eax
			invoke 	wsprintf,ADDR lBuff2,ADDR szSecondsF,eax
			lea 	eax,lBuff
			lea 	edx,lBuff2
			scall 	esi,eax,edx
			inc 	ebx
		.endif
		movzx 	eax,[TimeTakeA.wMilliseconds]
		.if 	eax
			invoke 	wsprintf,ADDR lBuff2,ADDR szMillscndsF,eax
			lea 	eax,lBuff
			lea 	edx,lBuff2
			scall 	esi,eax,edx
			inc 	ebx
		.endif
		
		pop 	esi
		
		.if 	ebx
			
			lea eax,lBuff
			strlen eax
			
			xchg 	eax,ecx
			lea 	eax,lBuff
			mov 	word ptr [eax+ecx],0A0Dh
			add 	ecx,2
			lea 	edx,lbrw
			invoke 	WriteFile,hFile,ADDR lBuff,ecx,edx,0 
		.endif
		
		; ------- result ------- ;
		movzx 	eax,[esi].wFinished
		test 	eax,eax
		.if 	zero?
			lea 	ebx,szSNotComplete
		.else
			lea 	ebx,szSComplete
		.endif
		
		strlen ebx
		
		xchg 	eax,ecx
		lea 	edx,lbrw
		invoke 	WriteFile,hFile,ebx,ecx,edx,0
		
		invoke 	MyZeroMemory,ADDR lBuff,1024
		invoke 	wsprintf,ADDR lBuff,ADDR szFollowResultF,[esi].dwFileScanned,[esi].dwThreatsDetected
		
		lea eax,lBuff
		strlen eax
		
		xchg 	eax,ecx
		invoke	WriteFile,hFile,ADDR lBuff,ecx,ADDR lbrw,0
		
		; ------- process and report all detected object that not take actions ------- ;
		.if 	[esi].dwThreatsDetected
			
			invoke 	SendMessage,hMainList,LVM_GETITEMCOUNT,0,0
			.if 	eax
				; ------- all detected object ready to report ------- ;
				mov 	ecx,eax
				push 	ecx
				
				lea eax,szTheseObjDtc
				strlen eax
				
				xchg 	ecx,eax
				invoke 	WriteFile,hFile,ADDR szTheseObjDtc,ecx,ADDR lbrw,0
				
				pop 	ecx
				
				mov 	[lvi.imask],LVIF_TEXT
				mov 	[lvi.cchTextMax],MAX_PATH
				@getdtcobj:
					push 	ecx
					dec 	ecx
					mov 	[lvi.iItem],ecx
					mov 	[lvi.iSubItem],0
					lea 	eax,lBuff2
					mov 	[lvi.pszText],eax
					invoke 	SendMessage,hMainList,LVM_GETITEM,0,ADDR lvi
					lea 	eax,lBuff2
					.if 	byte ptr [eax]
						invoke 	lstrcmp,ADDR lBuff2,ADDR szError
						.if 	!zero?
							mov 	[lvi.iSubItem],1
							lea 	eax,lBuff
							mov 	[lvi.pszText],eax
							invoke 	SendMessage,hMainList,LVM_GETITEM,0,ADDR lvi
							; ------- write path ------- ;
							
							lea eax,lBuff
							strlen eax
							
							mov 	ecx,eax
							lea 	eax,lBuff
							mov 	dword ptr [eax+ecx],00000A0DH
							add 	ecx,2
							invoke 	WriteFile,hFile,ADDR lBuff,ecx,ADDR lbrw,0
							; ------- write threat name ------- ;
							invoke 	lstrcmp,ADDR lBuff2,ADDR szSuspected1
							.if 	zero?
								lea 	edx,szHeurF
							.else
								lea 	eax,lBuff2
								cmp 	dword ptr [eax],'psuS'
								.if 	zero?
									lea 	edx,szHeurNameF
									jmp 	@F
								.endif
								cmp 	dword ptr [eax],'PSUS'
								.if 	zero?
									lea 	edx,szHeurNameF
									jmp 	@F
								.endif
								lea 	edx,szThreatNameF
							.endif
							@@:
							invoke 	wsprintf,ADDR lBuff,edx,ADDR lBuff2
							

							lea eax,lBuff
							strlen eax
							
							xchg 	ecx,eax
							invoke 	WriteFile,hFile,ADDR lBuff,ecx,ADDR lbrw,0
						.endif
					.endif
					pop 	ecx
					dec 	ecx
					jecxz 	@F
				jmp 	@getdtcobj
			@@:
			.else 
				; ------- all detected object was cleaned successfully ------- ;
				; report not available
				strlen offset szTheseObjClr
				
				xchg 	ecx,eax
				invoke 	WriteFile,hFile,ADDR szTheseObjClr,ecx,ADDR lbrw,0
			.endif
			
		.endif
		
		; ------- count ------- ;
		invoke 	MyZeroMemory,ADDR lBuff,1024
		mov 	eax,[esi].dwThreatsDetected
		.if 	eax
			lea 	eax,szSThreatDetc
		.else
			mov 	eax,[esi].dwFileScanned
			.if 	!eax
				lea 	eax,szSAborted
			.else
				lea 	eax,szSThreatNotdtc
			.endif
		.endif
		invoke 	wsprintf,ADDR lBuff,ADDR szFinalResultF,eax
		
		lea eax,lBuff
		strlen eax
		
		xchg 	eax,ecx
		invoke 	WriteFile,hFile,ADDR lBuff,ecx,ADDR lbrw,0
@endl2:
		invoke 	CloseHandle,hFile
	.endif
	
	invoke 	CreateFile,ADDR szTempFilePath,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	.if 	eax != -1
		mov 	hFile,eax
		
		invoke 	GetFileSize,hFile,0
		.if 	eax
			mov 	fSize,eax
			valloc 	eax
			.if 	eax
				mov 	memptr,eax
				
				invoke 	ReadFile,hFile,memptr,fSize,ADDR lbrw,0
				
				; ------- write to ctrl edit ------- ;
				invoke 	SetDlgItemText,hViewResultDlg,IDC_EDIT_VIEWRES,memptr
				
				vfree 	memptr
			.endif
		.endif
		invoke 	CloseHandle,hFile
	.endif

	assume 	esi:nothing
	
@endl:

	; ------- seh trapper ------- ;
	SehTrap 	__br
		ErrorDump 	"BuildResult",offset BuildResult,"viewresultdlg.asm"
	SehEnd 		__br

	mov 	eax,retv
	ret

BuildResult endp

align 16

TxtViewResProc proc hCtl:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD

	.if 	uMsg == WM_CHAR
		mov 	[wParam],0
	.endif

	invoke 	CallWindowProc,lpTxtViewRes,hCtl,uMsg,wParam,lParam
	ret 
TxtViewResProc endp

align 16


ViewResultProc proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	
	mov 	eax,uMsg
	.if 	eax == WM_INITDIALOG
	
		.if 	TimeForBlind
			invoke 	MakeRandomString,ADDR szRandomString,10
			invoke 	SetWindowText,hWin,ADDR szRandomString 
		.endif
		
		invoke 	GetDlgItem,hWin,IDC_EDIT_VIEWRES
		mov 	hTxtViewRes,eax
		invoke 	SetWindowLong,eax,GWL_WNDPROC,ADDR TxtViewResProc
		mov 	lpTxtViewRes,eax
		
		m2m 	hViewResultDlg,hWin
		call 	BuildResult 	
		
		invoke 	MakeFont,15,7,200,0,reparg("Courier New")
		mov 	hTerminalFont,eax
		
		
		invoke 	SendMessage,hTxtViewRes,WM_SETFONT,hTerminalFont,0
		invoke 	SetFocus,hWin
		invoke 	GetWindowTextLength,hTxtViewRes
		invoke 	SendMessage,hTxtViewRes,EM_SETSEL,eax,eax

	.elseif 	eax == WM_COMMAND
		mov 	eax,wParam
		and 	eax,0FFFFh
		.if 	eax == IDC_VIEWRES_NOTEPAD
			invoke 	ShellExecute,hWin,ADDR szOpen,ADDR szTempFilePath,0,ADDR szTempDir,SW_MAXIMIZE
		.elseif 	eax == IDC_VIEWRES_COPY
			invoke 	GetWindowTextLength,hTxtViewRes
			push 	eax
			invoke 	SendMessage,hTxtViewRes,EM_SETSEL,0,eax
			invoke 	SendMessage,hTxtViewRes,WM_COPY,0,0
			invoke 	SetFocus,hWin
			pop 	eax
			invoke 	SendMessage,hTxtViewRes,EM_SETSEL,eax,eax
		.elseif 	eax == IDC_VIEWRES_CLOSE
			jmp 	@close
		.endif
	.elseif 	eax == WM_CLOSE
	@close:
		invoke 	EndDialog,hWin,0
		invoke 	DeleteObject,hTerminalFont
	.endif
	
	xor 	eax,eax
	ret

ViewResultProc endp

align 16

ViewResult proc
	
	invoke 	DialogBoxParam,hInstance,IDD_VIEWRESULT,hMainWnd,ADDR ViewResultProc,0
	
	ret

ViewResult endp

