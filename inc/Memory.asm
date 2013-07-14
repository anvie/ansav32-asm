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

; ------- Memory.asm ------- ;
; for checking memory

.code

; ------- Checking memory thread ------- ;
CheckMemoryThread proc uses edi esi ebx lParam:DWORD
	
	LOCAL 	hSnap,sPos:DWORD
	LOCAL 	FilePath[MAX_PATH+1]:BYTE
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	LOCAL 	lpe:PROCESSENTRY32
	LOCAL 	tfi:THREATFULLINFO
	LOCAL 	MyPID:DWORD

	; ------- seh installation ------- ;
	SehBegin	__cmt
	
	mov 	ebx,MyZeroMemory
	
	lea 	eax,FilePath
	scall 	ebx,eax,MAX_PATH
	lea 	eax,lpe
	scall 	ebx,eax,sizeof PROCESSENTRY32
	lea 	eax,tfi
	scall 	ebx,eax,sizeof THREATFULLINFO

	mov 	MemCheck,1
	mov 	sPos,0
	
	call	GetCurrentProcessId
	mov 	MyPID,eax
	call 	InitBufferVirusInfo
	mov 	ebx,wsprintf
	
	invoke 	CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,0
	.if 	eax!=-1 && eax!=0
		mov 	hSnap,eax
		
		mov 	lpe.dwSize,sizeof PROCESSENTRY32
		invoke 	Process32First,hSnap,ADDR lpe
		.if 	eax
			.while 	eax
				
				mov 	eax,[lpe.th32ProcessID]
				; ------- Get process path ------- ;
				invoke 	GetProcessPath,ADDR FilePath,MAX_PATH,eax
				.if 	eax
					
					; ------- show process name to user ------- ;
					invoke 	MyZeroMemory,ADDR lBuff,MAX_PATH
					lea 	eax,lpe.szExeFile
					mov 	ecx,[lpe.th32ProcessID]
					lea 	edx,lBuff
					
					scall 	ebx,edx,reparg("Checking :  [ %s - %d ]"),eax,ecx
					add 	esp,4*4	; <-- fix stack ;
					invoke 	SetDlgItemText,hDlgStartup,IDC_STC_PROCESSNAME,ADDR lBuff
					
					cmp 	FilePath[0],'\'
					je 		@procnext
					mov 	eax,[lpe.th32ProcessID]
					test 	eax,eax
					je 		@procnext
					cmp 	eax,MyPID
					je 		@procnext
					cmp 	eax,4
					je 		@procnext
					cmp 	eax,ExplorerPID
					je 		@procnext
					
					; ------- Scan raw file ------- ;
					invoke 	MyZeroMemory,ADDR tfi,sizeof THREATFULLINFO
					lea 	eax,FilePath
					lea 	edx,tfi
					invoke 	CheckThisFile,eax,edx ;,0
					
					.if 	eax
						 	
						lea 	edx,tfi ;.szFilePath
						invoke 	BufferVirusInfoInsert,edx
					.endif
				.endif
@procnext:
				; ------- Update prog bar ------- ;
				inc 	sPos
				inc 	AllFilesCount
				invoke 	SendMessage,hStartupProgbar,PBM_SETPOS,sPos,0
				
				invoke 	MyZeroMemory,ADDR lBuff,MAX_PATH
				
				mLog 	"invoke 	PercentThis,sPos,dwPBMaxValue"
				
				invoke 	PercentThis,sPos,dwPBMaxValue
				lea 	edx,lBuff
				scall 	ebx,edx,offset szPercentF,eax
				add 	esp,4*3	; <-- fix stack ;
				
				mLog 	"invoke 	SetDlgItemText,hDlgStartup,IDC_STC_PERCENT,ADDR lBuff"
				
				invoke 	SetDlgItemText,hDlgStartup,IDC_STC_PERCENT,ADDR lBuff
				invoke 	UpdateWindow,hDlgStartup
				
				invoke 	Process32Next,hSnap,ADDR lpe
			.endw
			
			inc 	sPos
			invoke 	SendMessage,hStartupProgbar,PBM_SETPOS,sPos,0
			invoke 	MyZeroMemory,ADDR lBuff,MAX_PATH
			mov 	eax,sPos
			invoke 	PercentThis,eax,dwPBMaxValue
			lea 	edx,lBuff
			scall 	ebx,edx,offset szPercentF,eax
			add 	esp,4*3 	; <-- fix stack ;
			invoke 	SetDlgItemText,hDlgStartup,IDC_STC_PERCENT,ADDR lBuff
			invoke 	UpdateWindow,hDlgStartup
			
		.endif
		
		invoke 	CloseHandle,hSnap
	.else
		ViewError hDlgStartup,"Cannot snap process..."
	.endif
	
	invoke 	SendMessage,hStartupProgbar,PBM_SETPOS,dwPBMaxValue,0
	lea 	eax,lBuff
	scall 	ebx,eax,offset szPercentF,100
	add 	esp,4*3 	; <-- fix stack ;
	invoke 	SetDlgItemText,hDlgStartup,IDC_STC_PERCENT,ADDR lBuff
	invoke 	UpdateWindow,hDlgStartup
	
	; ------- Error handler ------- ;
	SehTrap 	__cmt				; --------------------[ -= Error handler for CheckMemoryThread =- ]
		ErrorDump "CheckMemoryThread",offset CheckMemoryThread,"Memory.asm"
	SehEnd		__cmt
	
	mov 	MemCheck,0
	
	invoke 	Sleep,100
	invoke 	EndDialog,hDlgStartup,0
	
	; ------- mem checking finish ------- ;
	mov 	InScanning,0
	
	ret

CheckMemoryThread endp

align 4

IFDEF 	DEBUG
; ------- Checking memory ------- ;
CheckMemoryFirst proc
	LOCAL 	hTID:DWORD
	
	; ------- seh instllation ------- ;
	SehBegin 	__cmf
	
	mLog 	"CheckMemoryFirst::"
	mLog 	"-Creating thread for CheckMemoryThread..."
	call 	InitScan
	invoke 	CreateThread,0,0,offset CheckMemoryThread,0,0,ADDR hTID
	.if 	eax
		mLog 	"..Success"
		invoke 	CloseHandle,eax
	.else
		mLog 	"..Failed"
		ViewError	hDlgStartup,"Cannot create thread for scanning process..."
	.endif

	; ------- seh trapper ------- ;
	SehTrap 	__cmf
	SehEnd 		__cmf

	ret
CheckMemoryFirst endp

ENDIF

align 4

; ------- Startup Dialog Procedure for scanning memory ------- ;
StartupDlgProc proc		hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	

	mov 	eax,uMsg
	.if 	eax == WM_INITDIALOG
		m2m 	hDlgStartup,hWin
		
		; ------- Populate progbar first ------- ;
		mLog 	"Enumerating all process..."
		call 	GetNumAllProcesses
		.if 	eax
			
			
			mLog 	"Process enumerated, now try to scan memory"
			mov 	dwPBMaxValue,eax
			invoke 	GetDlgItem,hWin,IDC_PROGBAR_STARTUP
			mov 	hStartupProgbar,eax
			invoke 	SendMessage,eax,PBM_SETRANGE32,0,dwPBMaxValue
			
			invoke 	ShowWindow,hWin,SW_SHOWDEFAULT
			invoke 	UpdateWindow,hWin
			
			call 	DontHookme
			
			; ------- Check it mem ------- ;
			invoke 	CheckMemoryThread,0
			
		.else	; ------- error ------- ;
			ViewError 	hWin,"Cannot enumerate all process!"
		.endif
		
	.endif
	
	xor 	eax,eax
	ret

StartupDlgProc endp

align 4

; ------- Startup dialog loader ------- ;
StartCheckMemoryFirst proc 

	invoke 	DialogBoxParam,hInstance,IDD_STARTUP,0,offset StartupDlgProc,0

	ret

StartCheckMemoryFirst endp

align 4

; ------- Find for specified file, is running in memory? ------- ;
IsRunInMemory? proc lpszPath:DWORD
	
	LOCAL 	hSnap,MyPID:DWORD
	LOCAL 	lpe:PROCESSENTRY32
	LOCAL 	FilePath[MAX_PATH+1]:BYTE
	LOCAL 	retv:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__irim
	
	invoke 	MyZeroMemory,ADDR lpe,sizeof PROCESSENTRY32
	invoke 	MyZeroMemory,ADDR FilePath,MAX_PATH
	mov 	hSnap,0
	mov 	retv,0
	call 	GetCurrentProcessId
	mov 	MyPID,eax
	
	invoke 	CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS,0
	.if 	eax!=-1 && eax!=0
		mov 	hSnap,eax
		mov 	[lpe.dwSize],sizeof PROCESSENTRY32
		invoke 	Process32First,hSnap,ADDR lpe
		.if 	eax
			.while eax
				
				mov 	eax,[lpe.th32ProcessID]
				test 	eax,eax
				jz 		@nx
				cmp 	eax,MyPID
				je 		@nx
				cmp 	eax,4
				je 		@nx
				
				; ------- Get process path ------- ;
				invoke 	GetProcessPath,ADDR FilePath,MAX_PATH,[lpe.th32ProcessID]
				.if 	eax
					
					; ------- compare it ------- ;
					invoke 	lstrcmpi,ADDR FilePath,lpszPath
					.if 	zero? ; sama
						mov 	eax,[lpe.th32ProcessID]
						mov 	retv,eax
						
						jmp 	@endsnap
					.endif
					
				.endif
				@nx:
				invoke 	Process32Next,hSnap,ADDR lpe
			.endw
		.endif
@endsnap:
		invoke 	CloseHandle,hSnap
	.endif

	; ------- seh trapper ------- ;
	SehTrap 	__irim
		ErrorDump 	"IsRunInMemory?",offset IsRunInMemory?,"memory.asm"
	SehEnd 		__irim
	
	mov 	eax,retv
	ret

IsRunInMemory? endp

align 4

QuickScanMem proc uses esi
	
	
	invoke 	SendMessage,hMainList,LVM_DELETEALLITEMS,0,0
	invoke 	UpdateWindow,hMainList
	mov 	esi,AppendLogConsole
	
	scall 	esi,reparg("Memory Quick scan start")
	call 	StartCheckMemoryFirst
	
	; ------- Check for existing threat in mem ------- ;
	mov 	MemCheck,1
	call 	CheckAndProcessBVI
	.if 	eax
		scall 	esi,offset szCheckCmpltDC
		invoke 	SetMainTxtStatus,STATUS_DETECTED
		invoke 	SetActionTbState,STATE_ENABLE
	.else
		scall 	esi,offset szCheckCmpltNDC
		invoke 	SetMainTxtStatus,STATUS_CLEAN
		invoke 	SetActionTbState,STATE_DISABLE
	.endif
	mov 	MemCheck,0
	
	call 	SetStatusClrTtl
	
	ret

QuickScanMem endp

align 16

