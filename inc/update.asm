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

;-------------------------------------- update.asm ----------------------------------------;

UPDATE_STARTED	equ 101
UPDATE_RUNNING equ 102
UPDATE_STATUS equ 103
UPDATE_SMLISTADD equ 104
UPDATE_SMLISTDEL equ 105
UPDATE_ERROR equ 106
STOP_ANSAVGUARD equ 107
UPDATE_QUERYANSAVGD equ 108

.data?
	hUpdateWnd dd ?
	hUpdateList dd ?
	UpdateReady dd ?
	UpdateStop dd ?
	hUpdatePB dd ?
	hUpdateInfo dd ?
	InUpdate dd ?
	StopUpdate dd ?
	hUpdateLblDldBuff dd ?
	MaxUpdatePBVal dd ?
	
	VERSIONINFO struct
		dwMajor 	dd ?
		dwMinor 	dd ?
		dwRevision 	dd ?
	VERSIONINFO ends
	
	UPDATEITEMINFO struct
		Version 		VERSIONINFO <>
		ContentCRC32 	dd ?
		ContentSize 	dd ?
		lpszItemUrlPath dd ?
		ItemUrlPathSize dd ?
	UPDATEITEMINFO ends
	
	ANSAVUPDATEINFO struct
		Version	VERSIONINFO <>	; <-- main update version ;
		Item 	UPDATEITEMINFO <>
		lpszUpdateNeeded dd ? 	; <-- pointer to str array ;
		UpdateNeededSize dd ?	; <-- size of array ;
	ANSAVUPDATEINFO ends
	
	StcUpdateVersion	VERSIONINFO <>	
	StcUpdate dd ?
	
	szUpdateBuff db MAX_PATH+1 dup(?)
	szUpdatePathNow db 1024 dup(?)
	szUserPassword db 12 dup(?)
.data

	szUpdateAsm db "update.asm"

	szUpdateLable db "Please don't do anything until update complete.",0
	szCGIPassF db "http://autoupdate.ansav.com/cgi-bin/verupd.cgi?passcode=%s",0 
	szHeaderDld db "http://autoupdate.ansav.com/update.h?",0
	szStaticUpdatePath db "http://www.ansav.com/abcde/update/vdb.dat?",0
	szMainUpdate db "update.h",0

	szUpdaterFileName db "anupdater.tmp",0
	szExvdbUpdf db " -> ( %d.%d.%d )",0
	
	szUpdateAvl db 'Update available. Click "Update Now" to start.',0
	szFinish db "Update Completed",0
	szUpdatedPro db "Fitur ini hanya tersedia untuk para donatur.",13,10
				 db "Silahkan anda update secara manual dengan men-download",13,10
				 db "ANSAV versi terbaru di www.ansav.com.",13,10
				 db "Apakah anda ingin langsung menuju ke www.ansav.com sekarang juga?",0
	szBytesDownload1F db "Download %d bytes.",0
	szBytesDownload2F db "Download %d of %d bytes.",0
	szAnsavGdNeed db "Update process will stop Ansav Guard.",13,10
				  db "You might be start Ansav Guard manualy if automation failed.",0
				  
	AutoUpdCheck dd 0
	StopAutoCheck dd 0
.code

UpdateStatus proc msg:DWORD

	cmp 	AutoUpdCheck,0
	je 		@F
		ret
	@@:

	invoke 	SetDlgItemText,hUpdateWnd,1010,msg
	invoke 	UpdateWindow,hUpdateWnd
IFDEF 	RELEASE
	invoke 	Sleep,500
ELSE
	invoke 	Sleep,100
ENDIF

	ret

UpdateStatus endp

align 16

Enuis proc uses edi esi ebx state:DWORD

	mov 	ebx,GetDlgItem
	mov 	esi,hUpdateWnd
	mov 	edi,EnableWindow
	
	scall 	ebx,esi,1001
	scall 	edi,eax,state
	scall 	ebx,esi,1008
	scall 	edi,eax,state
	scall 	ebx,esi,1007
	
	push	eax
		mov	eax,state
		RevEax
		xchg	edx,eax
	pop 	eax
	invoke 	ShowWindow,eax,edx
	
	.if 	state==TRUE
		invoke 	SetDlgItemText,hUpdateWnd,1010,reparg("Offline")
	.endif
	ret

Enuis endp

align 16

; ------- UPDATE DLGPROC ------- ;
UpdateDlgProc proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	
	mov 	eax,uMsg
	.if 	eax == WM_INITDIALOG
		
		cmp 	AutoUpdCheck,0
		je		@F
		mov 	UpdateReady,0
		mov 	StopAutoCheck,1
		
		; ------- wait for other instance destroyed ------- ;
		.if 	AutoUpdCheck
			return_0
		.endif
		
		mov 	StopAutoCheck,0 ;reset one
		cmp 	UpdateReady,0
		jne		@F
		cmp 	hAutUpdCheckThread,0
		je	 	@F
			invoke 	TerminateThread,hAutUpdCheckThread,0
		@@:
		
		mov2 	hUpdateWnd,hWin
		
		push 	esi	; <-- NEED POP ;
		mov 	esi,GetDlgItem
		push 	edi	; <-- NEED POP ;
		mov 	edi,hWin
		
		scall 	esi,edi,1005
		mov 	hUpdatePB,eax
		scall 	esi,edi,1003
		mov 	hUpdateList,eax
		scall 	esi,edi,1007
		mov 	hUpdateInfo,eax
		invoke 	ShowWindow,eax,SW_HIDE
		
		scall 	esi,edi,1011
		mov 	hUpdateLblDldBuff,eax
		
		mov 	esi,SetDlgItemText
		
		.if 	TimeForBlind
			mov 	eax,offset szAppName
		.else
			mov 	eax,reparg("ANSAV Update")
		.endif
		invoke 	SetWindowText,hWin,eax
		
		invoke 	SetDlgItemText,hWin,1008,reparg("Static only [Offline]")
		
		scall 	esi,hUpdateWnd,1010,reparg("Offline")
		scall 	esi,hWin,1007,offset szUpdateLable
		
		pop 	edi	; <-- POPED ;
		pop 	esi ; <-- POPED ;
		
		.if 	[lParam]==UPDATE_AUTOCHECK
			invoke 	ShowWindow,hWin,SW_HIDE
		.else
			invoke 	ShowWindow,hWin,SW_SHOW
		.endif
		
		invoke 	SetFocus,hWin
		
		cmp 	UpdateReady,0
		jne 	@updcheck2
		
	.elseif 	eax == WM_COMMAND
		mov 	eax,wParam
		and 	eax,0FFFFh
		.if 	eax==1004	; <-- CANCEL ;
			
			.if 	InUpdate
				invoke 	MessageBox,hWin, \
						reparg("Are you sure to abort update process?"), \
						offset szAppName,MB_ICONQUESTION OR MB_OKCANCEL
				.if 	eax!=IDOK
					return_0
				.endif
				mov 	StopUpdate,1
			.endif
			invoke 	GetDlgItemText,hWin,1004,offset szUpdateBuff,30
			.if 	szUpdateBuff[0]=='F'
				invoke 	PostQuitMessage,0
			.endif
			
			mov 	UpdateReady,0
			invoke 	EndDialog,hWin,0
			
		.elseif 	eax == 1001	; <-- CHECK/UPDATE ;
			
			invoke 	GetDlgItemText,hWin,1001,offset szUpdateBuff,30
			.if 	szUpdateBuff[0]=='C'
				
				invoke 	Enuis,FALSE
				invoke 	UpdateStatus,reparg("Check internet connection...")

				call	IsConnectedToInternet?
				.if 	!eax
					invoke 	MessageBox,hWin, \
							reparg("You don't have internet connection."), \
							offset szAppName,0
					push 	1
					call 	Enuis
					return_0
				.endif
				
@updcheck2:
				push 	1
				call 	Enuis
				
				; ------- build path main update ------- ;
				invoke 	lstrcpy,offset szUpdatePathNow,offset szHeaderDld
				invoke 	MakeRandomString,ADDR szUpdateBuff,10
				invoke 	lstrcat,offset szUpdatePathNow,ADDR szUpdateBuff
				;invoke 	lstrcat,offset szUpdatePathNow,offset szMainUpdate
				
				call 	CheckUpdate
				.if 	eax
					mov 	UpdateReady,eax
					invoke 	SetDlgItemText,hWin,1001,reparg("Update Now")
					invoke 	UpdateStatus,offset szUpdateAvl
				.else
					invoke 	UpdateStatus,reparg("Update not available")
				.endif
				
			.else

				; ------- UPDATE NOW!! ------- ;
				;call 	DoUpdate
				mov 	StopUpdate,0
				lea 	eax,DoUpdate
				invoke 	CreateThread,0,0,eax,0,0,ADDR brw
				invoke 	CloseHandle,eax
			.endif
		

		.elseif 	eax==1008	; <-- OFFLINE UPDATE ;
			
			;call 	OfflineUpdate
			mov 	StopUpdate,1
IFDEF 	BINOFFLINESUPPORT
			lea 	eax,OfflineUpdate
ELSE
			lea 	eax,StaticOnlyOffline
ENDIF
			invoke 	CreateThread,0,0,eax,0,0,ADDR brw
			invoke 	CloseHandle,eax

		.endif
		
	.endif
	
	xor 	eax,eax
	ret

UpdateDlgProc endp

align 16

; ------- update ------- ;
Update proc

	.if 	!InScanning && !InAction
		invoke 	DialogBoxParam,hInstance,IDD_UPDATE,hMainWnd,offset UpdateDlgProc,0
	.else
		invoke 	MessageBox,hMainWnd,reparg("Please stop current progress first"), \
				offset szAppName,0
	.endif

	ret

Update endp

align 16

.data
	UpdateFileSize dd ?
	UpdateFileCRC32 dd ?
	updatefile db MAX_PATH dup(?)
	ItemUpdateUrlPath db MAX_PATH*2 dup(?)
.code

;-------------------------------------- STUFF UPDATE PROCEDURE ----------------------------------------;
CheckUpdate proc uses edi esi ebx

	LOCAL 	hNet,hUrl,hFile,bufflen,lbrw:DWORD
	LOCAL 	fSize,UItem:DWORD
	LOCAL 	buff[1024*2]:BYTE
	LOCAL 	retv:DWORD
	
	
	AccInt MACRO lbl 
		cmp 	AutoUpdCheck,1
		jne 	@F
			cmp 	StopAutoCheck,1
			je 		lbl
		@@:
	endm
	
	
	mov 	ebx,MyZeroMemory
	
	lea 	edi,updatefile
	scall 	ebx,edi,MAX_PATH
	lea 	esi,buff
	scall 	ebx,esi,1024*2
	mov 	retv,0
	
	invoke 	Enuis,FALSE
	invoke 	UpdateStatus,reparg("Connecting...")
	
	invoke 	lstrcpy,edi,offset szTempDir

	invoke 	TruePath,edi
	invoke 	lstrcat,edi,offset szMainUpdate

	invoke 	AppendLogConsole,reparg("Open internet connection...")

	mov 	bufflen,0
	invoke 	InternetOpen,offset szMyPath, \
			INTERNET_OPEN_TYPE_PRECONFIG, \
			0,0,0
			
	.if 	eax==-1
		invoke 	AppendLogConsole,reparg("Internet connection not ready.")
		
		call 	cannotconnect
		invoke 	Enuis,TRUE
		return_0
	.endif
	mov 	hNet,eax
	
	AccInt 	@wsint
	
	push 	0
	call 	SetLastError
	invoke 	InternetOpenUrl,hNet, \
			offset szUpdatePathNow,0,0,0,0
	mov 	hUrl,eax
	call 	GetLastError
	.if 	!eax
		
		AccInt 	@wsint2
		
		; ------- if ERROR SUCCESS ------- ;
		invoke 	FileExist,edi
		.if 	eax
			invoke 	SetFileAttributes, \
					edi, \
					FILE_ATTRIBUTE_NORMAL
			invoke 	DeleteFile,edi
			.if 	!eax
				call 	cannotcrttmp
			@wsint2:
				invoke  InternetCloseHandle,hUrl	; <-- cleanup ;
			@wsint:
				invoke 	InternetCloseHandle,hNet
				invoke 	Enuis,TRUE
				return_0
			.endif
		.endif
		
		invoke 	CreateFile,edi, \
				GENERIC_READ or GENERIC_WRITE, \
				FILE_SHARE_READ or FILE_SHARE_WRITE, \
				0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0
		.if 	eax && eax!=-1
			mov 	hFile,eax
			
			AccInt	@err
			
			invoke 	SetFilePointer,eax,0,0,FILE_BEGIN
			
			invoke 	UpdateStatus,reparg("Check for available update...")
			
			mov 	bufflen,0
			invoke 	InternetReadFile,hUrl,esi,1024,ADDR bufflen
			.while 	bufflen
				
				; ------- check for rto ------- ;
				cmp 	dword ptr [esi],'OD!<'
				.if 	zero?
					cmp 	AutoUpdCheck,1
					je 		@F
					ViewError	hUpdateWnd,"Cannot make connection to remote server. Request timed out!"
					@@:
					jmp 	@err
				.endif
				
				invoke 	wsprintf,offset szUpdateBuff,offset szBytesDownload1F,bufflen
				invoke 	SetWindowText,hUpdateLblDldBuff,offset szUpdateBuff
				
				
				invoke 	WriteFile,hFile,esi,bufflen,ADDR lbrw,0 
				.if 	!eax
					.if 	!AutoUpdCheck
						call 	cannotdld
					.endif
				@err:
					invoke 	CloseHandle,hFile
					invoke  InternetCloseHandle,hUrl	; <-- cleanup ;
					invoke 	InternetCloseHandle,hNet
					invoke 	Enuis,TRUE
					return_0
				.endif
				
				AccInt 	@err
				
				invoke 	InternetReadFile,hUrl,esi,1024,ADDR bufflen
			.endw
			
			invoke 	CloseHandle,hFile
		.endif
		invoke  InternetCloseHandle,hUrl	; <-- cleanup ;
		invoke 	InternetCloseHandle,hNet
	.else
		.if 	!AutoUpdCheck
			call 	cannotdld
		.endif
		invoke 	InternetCloseHandle,hNet	; <-- cleanup ;
		invoke 	Enuis,TRUE
		return_0
	.endif
	
	mov 	hFile,0

	; ------- check for version ------- ;
	invoke 	CreateFile,edi, \
			GENERIC_READ,FILE_SHARE_READ, \
			0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	.if 	eax && eax!=-1
		mov 	hFile,eax
		
		invoke 	GetFileSize,eax,0
		.if 	eax
			mov 	 fSize,eax
			
			valloc 	eax
			.if 	eax
				mov 	esi,eax
				
				invoke 	ReadFile,hFile,esi,fSize,ADDR lbrw,0
				.if 	!eax || (lbrw<20)	; <-- corrupted ;
					
					.if 	!AutoUpdCheck
						ViewError	hUpdateWnd,"Cannot download update or data corrupt."
					.endif
		error_0:
					vfree esi	; ------- if ERROR ------- ;
					invoke 	CloseHandle,hFile
					invoke 	Enuis,TRUE
					return_0
				.endif
				
				assume 	esi:ptr ANSAVUPDATEINFO
				
				; ------- CHECK VERSION ------- ;
				mov 	eax,[esi].Version.dwMajor
				mov 	ecx,[esi].Version.dwMinor
				mov 	edx,[esi].Version.dwRevision
				
				call 	checkversion
				.if 	!eax
					;call 	noneedupdate
					
					invoke 	CloseHandle,hFile
					mov 	hFile,0
					
					; ------- CHECK FOR STATIC VDB UPDATE ------- ;
					call 	CheckExVdb
					.if 	eax
						cmp 	AutoUpdCheck,1
						je 		@skip0
						
						; ------- build vdb static version info ------- ;
						lea 	ebx,szUpdateBuff
						invoke 	MyZeroMemory,ebx,MAX_PATH
						invoke 	wsprintf,ebx,
								offset szExvdbUpdf,
								[StcUpdateVersion.dwRevision],
								[StcUpdateVersion.dwMinor],
								[StcUpdateVersion.dwMajor]
						
						invoke 	SendMessage,hUpdateList,LB_RESETCONTENT,0,0
						invoke 	SendMessage,hUpdateList,LB_ADDSTRING,0, \
								reparg("External static database (daily update)")
								
						@skip0:
						vfree 	esi
						mov 	StcUpdate,1
						jmp 	@showupdinfo
					.endif
					
					.if 	!AutoUpdCheck
						call 	noneedupdate
					.endif
					jmp 	error_0
				.endif
				
				invoke 	CloseHandle,hFile
				mov 	hFile,0
				
				cmp 	AutoUpdCheck,1
				je 		@skip1
				
				; ------- show needed component to update ------- ;
				invoke 	SendMessage,hUpdateList,LB_RESETCONTENT,0,0
				mov		ebx,[esi].lpszUpdateNeeded
				add 	ebx,esi
				
				; ------- check accessible ------- ;
				mov 	eax,fSize
				add 	eax,esi
				cmp 	ebx,eax
				jnb 	error_0	; <-- corrupted ;
				
	@showupdinfo:
				.while 	byte ptr [ebx]
					
					invoke 	SendMessage,hUpdateList,LB_ADDSTRING,0,ebx
					
					.while 	byte ptr [ebx]
						inc 	ebx
					.endw
					inc 	ebx
					
				.endw
				
				@skip1:
				cmp 	StcUpdate,1
				je 		@alreadybuild
				
				; ------- get updated item info to download ------- ;
				mov  	eax,[esi].Item.lpszItemUrlPath
				add 	eax,esi
				lea 	ebx,ItemUpdateUrlPath
				invoke 	lstrcpy,ebx,eax
				
				mov2 	UpdateFileSize,[esi].Item.ContentSize
				mov2 	UpdateFileCRC32,[esi].Item.ContentCRC32
				vfree 	esi
				
				assume 	esi:nothing
				
	@alreadybuild:
				mov 	retv,1
			.endif ; valloc eax
		.else
			ViewError	hUpdateWnd,offset szMemAllocError
		.endif
		
		.if 	hFile
			invoke 	CloseHandle,hFile
		.endif 
	.endif
	
	invoke 	Enuis,TRUE
	mov 	eax,retv
	ret
CheckUpdate endp

cannotconnect:
	ViewError hUpdateWnd,"Cannot make internet connection."
	retn
	
cannotcrttmp:
	ViewError hUpdateWnd,"Cannot create temporary file"
	retn
	
cannotdld:
	ViewError	hUpdateWnd,"Cannot make connection to update server :("
	retn
	
noneedupdate:
	invoke 	MessageBox,hUpdateWnd, \
			reparg("No update available at this time. Check it later."), \
			offset szAppName, \
			MB_ICONINFORMATION OR MB_OK
	retn
	
checkversion:
		.if 	(eax==VerMajor) && \
				(ecx==VerMinor) && \
				(edx==VerRevision) 
			xor eax,eax
			retn
		.else
			.if 	eax>VerMajor
				return_1
			.elseif eax<VerMajor
				jmp @F
			.endif
			.if 	ecx>VerMinor
				return_1
			.elseif ecx<VerMinor
				jmp @F
			.endif
			.if 	edx>VerRevision
				return_1
			.endif
		.endif
		@@:
		xor eax,eax
	retn

corrupted:
	ViewError	hUpdateWnd,"Update failed, file corrupted. :("
	retn

cannotextract:
	ViewError	hUpdateWnd,"Cannot extract binary data. :("
	retn
	
notvalidupdater:
	ViewError	hUpdateWnd,"Not valid ANSAV bin Update."
	retn
	
updateaborted:
	invoke 	MessageBox,hUpdateWnd, \
			reparg("Update aborted by user!"), \
			offset szAppName,MB_ICONEXCLAMATION
	retn
	
invalidpass:
	invoke 	MessageBox,hUpdateWnd, \
			reparg("Invalid Passcode."), \
			offset szAppName,MB_ICONEXCLAMATION
	retn
	
align 16

DoUpdate proc uses edi esi ebx
	
	LOCAL 	hNet,hUrl,bufflen,lbrw:DWORD
	LOCAL 	BytesTransfer:DWORD
	LOCAL 	hFile,hFile2,fSize,UItem:DWORD
	LOCAL 	buff[1024*2]:BYTE
	LOCAL 	tmp:DWORD
	
	
IFDEF 	RELEASE
	.if 	!UpdateReady
		call 	cannotdld
		return_0
	.endif
ENDIF

	mov 	InUpdate,1
	invoke 	Enuis,FALSE
	
	.if 	StcUpdate
		
		invoke 	UpdateStatus,reparg("Updating static database. Please wait...")
		
		; ------- do static update vdb.dat just copy it ------- ;
		mov 	esi,offset szUpdateBuff
		invoke 	lstrcpy,esi,offset szMyDir
		invoke 	TruePath,esi
		invoke 	lstrcat,esi,offset szVdbDat
		invoke 	GetFileAttributes,esi
		.if 	eax!=-1
			mov 	tmp,eax
			invoke 	SetFileAttributes,esi,FILE_ATTRIBUTE_NORMAL
			invoke 	DeleteFile,esi
		.else
			mov 	tmp,FILE_ATTRIBUTE_NORMAL
		.endif
		invoke 	CopyFile,offset szUpdatePathNow,esi,0
		.if 	!eax
			ViewError hUpdateWnd,reparg("Cannot update file vdb.dat")
			mov 	InUpdate,0
			return_0
		.endif
		invoke 	SetFileAttributes,esi,tmp
		
		invoke 	MessageBox,hUpdateWnd,reparg("Update complete. Please restart ANSAV to take effect."),
				offset szAppName,MB_OK or MB_ICONINFORMATION
				
		invoke 	SetDlgItemText,hUpdateWnd,1004,reparg("FINISH")
		invoke 	UpdateStatus,offset szFinish
		mov 	InUpdate,0
		return_1
	.endif
	
	invoke 	UpdateStatus,reparg("Download latest component. Please wait...")
	

	; ------- dynamic bin update ------- 
	lea 	edi,szUpdatePathNow
	invoke 	wsprintf,edi,offset szCGIPassF,offset szUserPassword
	
	; -------------- ;
	
	; ------- DOWNLOAD UPDATED ITEM ------- ;
	mov 	esi,offset updatefile
	mov 	bufflen,0
	invoke 	InternetOpen,offset szMyPath, \
			INTERNET_OPEN_TYPE_PRECONFIG, \
			0,0,0
			
	.if 	eax==-1
		call 	cannotconnect
		invoke 	Enuis,TRUE
		mov 	InUpdate,0
		return_0
	.endif
	mov 	hNet,eax
	
	push 	0
	call 	SetLastError
	
	invoke 	InternetOpenUrl,hNet, \
			edi,0,0,0,0
	mov 	hUrl,eax
	call 	GetLastError
	
	.if 	!eax
		
		mov 	edi,InternetCloseHandle
		
		; ------- if ERROR SUCCESS ------- ;
		invoke 	FileExist,esi
		.if 	eax
			invoke 	SetFileAttributes,esi,FILE_ATTRIBUTE_NORMAL
			invoke 	DeleteFile,esi
			.if 	!eax
				scall 	edi,hUrl	; <-- cleanup ;
				scall 	edi,hNet	; <-- cleanup ;
				call 	cannotcrttmp
				invoke 	Enuis,TRUE
				mov 	InUpdate,0
				return_0
			.endif
		.endif
		
		invoke 	ShowWindow,hUpdateLblDldBuff,SW_SHOW
		
		invoke 	CreateFile,esi, \
				GENERIC_READ or GENERIC_WRITE, \
				FILE_SHARE_READ or FILE_SHARE_WRITE, \
				0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0
		.if 	eax && eax!=-1
			
			mov 	hFile,eax
			
			lea 	esi,buff
			
			invoke 	SendMessage,hUpdatePB, PBM_SETRANGE32,0,UpdateFileSize
			
			invoke 	SetFilePointer,eax,0,0,FILE_BEGIN
			
			mov 	BytesTransfer,0
			mov 	bufflen,1024
			invoke 	InternetReadFile,hUrl,esi,1024,ADDR bufflen
			cmp 	dword ptr [esi],078657620h
			jne 	@F
				.if 	!AutoUpdCheck
					ViewError	hUpdateWnd,"Bandwidth limit exceeded, autoupdate aborted"
				.endif
				jmp @cls_01
			@@:
			.while 	bufflen
				
				
				mov 	eax,bufflen
				add 	BytesTransfer,eax
				invoke 	wsprintf,offset szUpdateBuff, \
						offset szBytesDownload2F, \
						BytesTransfer,UpdateFileSize
				invoke 	SetWindowText,hUpdateLblDldBuff, \
						offset szUpdateBuff
				invoke 	SendMessage,hUpdatePB, PBM_SETPOS,BytesTransfer,0
				
				.if 	StopUpdate
					call 	updateaborted
			@cls_01:
					invoke 	CloseHandle,hFile
					scall 	edi,hUrl	; <-- cleanup ;
					scall 	edi,hNet	; <-- cleanup ;
					invoke 	Enuis,TRUE
					mov 	InUpdate,0
					return_0
				.endif
				
				cmp 	dword ptr [esi],'REFD'
				je 		@invalidcode
				
				invoke 	WriteFile,hFile,esi,bufflen,ADDR lbrw,0
				.if 	!eax
					.if 	!AutoUpdCheck
						call 	cannotdld
					.endif
					invoke 	CloseHandle,hFile
					scall 	edi,hUrl	; <-- cleanup ;
					scall 	edi,hNet	; <-- cleanup ;
					invoke 	Enuis,TRUE
					mov 	InUpdate,0
					return_0
				.endif
				
				invoke 	InternetReadFile,hUrl,esi,1024,ADDR bufflen
			.endw
			
			.if 	BytesTransfer<10
@invalidcode:
				invoke 	CloseHandle,hFile; ------- INVALID DONATOUR ------- ;
				scall 	edi,hUrl	; <-- cleanup ;
				scall 	edi,hNet	; <-- cleanup ;
				call 	invalidpass
				invoke 	ShowWindow,hUpdateLblDldBuff,SW_HIDE
				invoke 	Enuis,TRUE
				mov 	InUpdate,0
				return_0
			.endif
			
			invoke 	SetWindowText,hUpdateLblDldBuff,reparg("Download Completed.")
			
			invoke 	CloseHandle,hFile
		.endif
		scall 	edi,hUrl	; <-- cleanup ;
		scall 	edi,hNet	; <-- cleanup ;
	.else
		.if !AutoUpdCheck
			call 	cannotdld	; <-- cleanup ;
		.endif
		scall 	edi,hNet	; <-- cleanup ;
		invoke 	Enuis,TRUE
		mov 	InUpdate,0
		return_0
	.endif
	
	push 	offset updatefile

	call 	DoOfflineUpdate
	.if 	eax
		invoke 	SetDlgItemText,hUpdateWnd,1004,reparg("FINISH")
		invoke 	UpdateStatus,offset szFinish
		
		; ------- forcely exit ------- ;
		jmp 	GlobalExit
	.endif
	
	mov 	InUpdate,0
	ret
DoUpdate endp


align 16


UpdateFuncProc PROC uses esi wParam:DWORD, lParam:DWORD

	mov 	esi,SendMessage
	
	mov 	UpdateStop,0
	
	mov 	eax,wParam
	.if 	eax == UPDATE_STARTED
		
		mov2	MaxUpdatePBVal,lParam
		; -------  set prog bar max value ------- ;
		scall 	esi,hUpdatePB, \
				PBM_SETRANGE32,0,lParam
		
	.elseif 	eax == UPDATE_RUNNING
	
		; ------- INC VALUE ------- ;
		scall 	esi,hUpdatePB, \
				PBM_SETPOS,lParam,0
		
	.elseif 	eax == UPDATE_STATUS
	
		invoke 	UpdateStatus,lParam
		
	.elseif 	eax == UPDATE_SMLISTADD
	
		scall 	esi,hUpdateList, \
				LB_ADDSTRING,wParam,lParam
		
	.elseif 	eax == UPDATE_SMLISTDEL
	
		scall 	esi,hUpdateList, \
				LB_DELETESTRING,wParam,lParam
		
	.elseif 	eax == UPDATE_ERROR
		ViewError	hUpdateWnd,lParam
		
	.elseif 	eax == STOP_ANSAVGUARD
		
		scall 	esi,hUpdateList, \
				LB_ADDSTRING,0,reparg("Trying to stop Ansav Guard...")
		
		invoke 	MessageBox,hUpdateWnd,offset szAnsavGdNeed,offset szAppName,MB_ICONINFORMATION
		invoke 		EnableDisableAG,2
		.if 	!eax
			ViewError	hUpdateWnd, \
			"Cannot stop Ansav Guard, please stop it first manualy then try again."
			mov 	UpdateStop,1
		.endif
		
	.elseif 	eax == 1001 ;; NEED FOR DEBUGGING
IFDEF 	DEBUG
		invoke 	AppendLogConsole,lParam
ENDIF
	.elseif 	eax == UPDATE_QUERYANSAVGD
		invoke 	IsAnsavGuardActive?
		.if 	eax
			mov 	eax,2
		.else
			mov 	eax,0
		.endif
		ret
	.endif
	
	mov 	eax,UpdateStop
	RevEax
	ret
UpdateFuncProc endp

align 16

IFDEF 	DEBUG

;-------------------------------------- UPDATE HEADER MAKER ----------------------------------------;
BuildUpdateFile proc uses edi esi ebx
	
	LOCAL 	aui:ANSAVUPDATEINFO
	LOCAL 	tmp,lbrw:DWORD
	
	invoke 	CreateFile,reparg("update.h"), \
			GENERIC_WRITE,FILE_SHARE_WRITE, \
			0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0
	.if 	eax!=-1
		mov 	esi,eax
		
		lea 	edi,aui
		invoke 	MyZeroMemory,edi,sizeof ANSAVUPDATEINFO
		
		assume 	edi:ptr ANSAVUPDATEINFO
		
		mov2 	[edi].Version.dwMajor,VerMajor
		inc 	[edi].Version.dwMajor
		mov2	[edi].Version.dwMinor,VerMinor
		inc 	[edi].Version.dwMinor
		mov2 	[edi].Version.dwRevision,VerRevision
		inc 	[edi].Version.dwRevision
		
		mov2 	[edi].Item.Version.dwMajor,VerMajor
		inc 	[edi].Item.Version.dwMajor
		mov2 	[edi].Item.Version.dwMinor,VerMinor
		inc 	[edi].Item.Version.dwMinor
		mov2 	[edi].Item.Version.dwRevision,VerRevision
		inc 	[edi].Item.Version.dwRevision
		
		invoke 	SetFilePointer,esi,0,0,FILE_BEGIN
		invoke 	WriteFile,esi,edi,sizeof ANSAVUPDATEINFO,ADDR lbrw,0 
		
		invoke 	SetFilePointer,esi,0,0,FILE_CURRENT
		mov2 	[edi].lpszUpdateNeeded,eax
		
		push 	ebx
		mov 	ebx,WriteFile
		push 	edi
		lea 	edi,lbrw
		
		scall 	ebx,esi,reparg("Main Engine version 1.4.5"),26,edi,0
		scall 	ebx,esi,reparg("Ansav Guard"),12,edi,0
		scall 	ebx,esi,reparg("Fixer Engine"),13,edi,0
		scall 	ebx,esi,reparg("Static External Database"),25,edi,0
		
		pop 	edi
		pop 	ebx
		
		; ------- null ------- ;
		mov 	tmp,0
		mov 	ebx,WriteFile
		
		lea 	eax,lbrw
		lea 	edx,tmp
		scall 	ebx,esi,edx,4,eax,0
		
		invoke 	GetFileSize,esi,0
		sub 	eax,sizeof ANSAVUPDATEINFO
		mov 	[edi].UpdateNeededSize,eax
		
		
		; ------- set updated path url ------- ;
		invoke 	SetFilePointer,esi,0,0,FILE_CURRENT
		mov 	[edi].Item.lpszItemUrlPath,eax
		
IFDEF 	RELEASE
		mov 	edx,reparg("http://omponk.routelink.net/update/update.bin")
ELSE
		mov 	edx,reparg("update.bin")
ENDIF
		push 	edx
		invoke 	lstrlen,edx
		mov 	ecx,eax
		inc 	ecx
		pop 	edx
		lea 	eax,lbrw
		scall 	ebx,esi,edx,ecx,eax,0
		mov 	[edi].Item.ItemUrlPathSize,MAX_PATH
		
		 
		invoke 	SetFilePointer,esi,0,0,FILE_BEGIN
		lea 	eax,lbrw
		scall 	ebx,esi,edi,sizeof ANSAVUPDATEINFO,eax,0
		
		assume 	edi:nothing
		
		invoke 	CloseHandle,esi
	.endif
	ret

BuildUpdateFile endp

align 16

BuildUpdateBinFile proc uses esi ebx	lpFile:DWORD
	LOCAL 	hFile,fSize:DWORD
	
	
	invoke 	CreateFile,lpFile,GENERIC_READ or \
			 GENERIC_WRITE,FILE_SHARE_READ or \
			 FILE_SHARE_WRITE,0,OPEN_EXISTING, \
			 FILE_ATTRIBUTE_NORMAL,0
	.if 	eax!=-1
		mov 	hFile,eax
		
		invoke 	GetFileSize,eax,0
		.if 	eax
			mov 	fSize,eax
			add 	eax,sizeof UPDATEITEMINFO
			
			valloc 	eax
			.if 	eax
				mov 	esi,eax
				add 	eax,sizeof UPDATEITEMINFO
				mov 	ebx,eax
				invoke 	ReadFile,hFile,eax,fSize,ADDR brw,0
				
				assume 	esi:ptr UPDATEITEMINFO
				
				mov2 	[esi].Version.dwMajor,VerMajor
				inc 	[esi].Version.dwMajor
				mov2	[esi].Version.dwMinor,VerMinor
				inc 	[esi].Version.dwMinor
				mov2 	[esi].Version.dwRevision,VerRevision
				inc 	[esi].Version.dwRevision
				
				call 	crcInit
				invoke 	crcCalc,ebx,fSize
				mov 	[esi].ContentCRC32,eax
				
				mov2 	[esi].ContentSize,fSize
				mov 	[esi].lpszItemUrlPath,0	; <-- don't needed ;
				mov 	[esi].ItemUrlPathSize,0 ; <-- don't needed ;
				
				assume 	esi:nothing
				
				invoke 	SetFilePointer,hFile,0,0,FILE_BEGIN
				
				mov 	eax,fSize
				add 	eax,sizeof UPDATEITEMINFO
				invoke 	WriteFile,hFile,esi,eax,ADDR brw,0
				
				vfree 	esi
			.endif
		.endif
		
		invoke 	CloseHandle,hFile
	.endif
	
	ret

BuildUpdateBinFile endp

align 16

ENDIF ;;DEBUG


DoOfflineUpdate proc uses edi esi lpszFile:DWORD
	
	LOCAL 	lbrw,hFile,hFile2,fSize:DWORD
	LOCAL 	szUpdaterFile[MAX_PATH+1]:BYTE
	LOCAL 	hUpdateMod:DWORD
	LOCAL 	retv:DWORD
	
	mov 	retv,0
	
	mov 	InUpdate,1
	
	; ------- create snapshot ------- ;
	call 	CreateUpdSnap
	
	; ------- now work offline ------- ;
	invoke 	CreateFile,lpszFile, \
			GENERIC_READ, \
			FILE_SHARE_READ,0, \
			OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	.if 	eax && eax!=-1
		mov 	hFile,eax
		
		invoke 	GetFileSize,eax,0
		.if 	eax
			mov 	fSize,eax
			valloc 	eax
			.if 	eax
				mov 	esi,eax
				invoke 	ReadFile,hFile,esi,fSize,ADDR lbrw,0
				.if 	!eax
					.if 	!AutoUpdCheck
						call	cannotdld
					.endif
					invoke 	CloseHandle,hFile
					vfree 	esi
				.endif
				
				assume 	esi:ptr UPDATEITEMINFO
				
				; ------- check for valid update ------- ;
				call 	crcInit
				mov 	eax,sizeof UPDATEITEMINFO
				lea 	edx,[esi+eax]
				mov 	ecx,fSize
				sub 	ecx,eax
				invoke 	crcCalc,edx,ecx
				cmp 	eax,[esi].ContentCRC32
				.if 	!zero?
					vfree 	esi	; <-- cleanup ;
					invoke 	CloseHandle,hFile
					call 	notvalidupdater
					invoke 	Enuis,TRUE
					call 	@freecache
					mov 	InUpdate,0
					return_0
				.endif
				
				
				mov 	eax,[esi].Version.dwMajor
				mov 	ecx,[esi].Version.dwMinor
				mov 	edx,[esi].Version.dwRevision
				
				call 	checkversion
				.if 	!eax
					ViewError	hUpdateWnd,"Cannot resolve for new update, please flush your cache first."
					vfree 	esi	; <-- cleanup ;
					invoke 	CloseHandle,hFile
					invoke 	Enuis,TRUE
					call 	@freecache
					mov 	InUpdate,0
					return_0
				.endif
				
				assume 	esi:nothing
				
				; ------- VERSION & VALID. OK LET'S UPDATE ------- ;
				
				; ------- extract bin dll file ------- ;
				lea 	edi,szUpdaterFile
				invoke 	MyZeroMemory,edi,MAX_PATH
				invoke 	lstrcpy,edi,offset szTempDir
				invoke 	TruePath,edi
				invoke 	lstrcat,edi,offset szUpdaterFileName
				
				invoke 	CreateFile,edi, \
						GENERIC_WRITE, \
						FILE_SHARE_WRITE,0, \
						CREATE_ALWAYS, \
						FILE_ATTRIBUTE_NORMAL,0
				.if 	eax
					mov 	hFile2,eax
					mov 	edx,esi
					
					mov 	eax,sizeof UPDATEITEMINFO
					add 	edx,eax
					mov 	ecx,fSize
					sub 	ecx,eax
					invoke 	WriteFile,hFile2,edx,ecx,ADDR brw,0
					invoke 	CloseHandle,hFile2
					
					; ------- now load her ------- ;
					invoke 	LoadLibrary,edi
					.if 	!eax
						vfree 	esi	; <-- cleanup ;
						invoke 	CloseHandle,hFile
						call 	corrupted
						invoke 	Enuis,TRUE
						call 	@freecache
						mov 	InUpdate,0
						return_0
					.endif
					mov 	hUpdateMod,eax
					
					; ------- prepare hook ------- ;
					mov 	UpdateStop,0
					
					invoke 	GetProcAddress,hUpdateMod,reparg("update")
					.if 	!eax
						vfree 	esi	; <-- cleanup ;
						invoke 	CloseHandle,hFile
						call 	corrupted
						invoke 	Enuis,TRUE
						call 	@freecache
						mov 	InUpdate,0
						return_0
					.endif
					
					lea 	edx,UpdateFuncProc
					push 	edx
					call	eax	; <-- take out control ;
					mov 	retv,eax
					
					
					; ------- ; ------- ; ------- JUST WAIT ------- ; ------- ; ------- ;
					.if 	!eax
						invoke 	SendMessage, \
								hUpdatePB, \
								PBM_SETPOS,0,0
					.endif
					
					invoke 	FreeLibrary,hUpdateMod
					
				.else
					call 	cannotextract
				.endif
				
				vfree esi
			.else
				ViewError	hUpdateWnd,offset szMemAllocError
			.endif
		.endif
		
		invoke 	CloseHandle,hFile
	.endif

	mov 	InUpdate,0
	mov 	eax,retv
	ret

@freecache:
	invoke 	lstrcpy,offset szUpdateBuff,offset szMyDir
	invoke 	TruePath,offset szUpdateBuff
	invoke 	lstrcat,offset szUpdateBuff,offset szAnupdCache
	invoke 	SetFileAttributes,offset szUpdateBuff,FILE_ATTRIBUTE_NORMAL
	invoke 	DeleteFile,offset szUpdateBuff
	retn
	

DoOfflineUpdate endp

align 16

OfflineUpdate proc uses esi
	
	LOCAL 	ofn:OPENFILENAME
	LOCAL 	fname[MAX_PATH+1]:BYTE
	
	mov 	esi,MyZeroMemory
	mov 	esi,MyZeroMemory
	
	lea 	eax,ofn
	scall 	esi,eax,sizeof OPENFILENAME
	lea 	eax,fname
	scall 	esi,eax,MAX_PATH
	
	mov 	[ofn.lStructSize],sizeof OPENFILENAME
	mov2 	[ofn.hwndOwner],hUpdateWnd
	mov2 	[ofn.hInstance],hInstance
	mov 	[ofn.nMaxFile],256
	lea 	eax,fname
	mov		[ofn.lpstrFile],eax
	mov 	[ofn.lpstrFilter],offset szMaskAllFile
	invoke 	GetOpenFileName,ADDR ofn
	
	.if 	eax && fname[0]
		invoke 	Enuis,FALSE
		invoke 	DoOfflineUpdate,ADDR fname
		push 	eax
			invoke 	Enuis,TRUE
		pop 	eax
		.if 	eax
			invoke 	SetDlgItemText,hUpdateWnd,1004,reparg("FINISH")
			invoke 	UpdateStatus,offset szFinish
		.endif
	.endif
	
	ret

OfflineUpdate endp

align 16

CheckExVdb proc  uses edi esi ebx
	
	LOCAL 	hNet,hUrl,bufflen:DWORD
	LOCAL 	hFile:DWORD
	LOCAL 	tmp:DWORD
	LOCAL 	retv:DWORD
	
	xor 	eax,eax
	mov 	retv,eax
	mov 	StcUpdate,eax
	
	
	invoke 	InternetOpen,offset szMyPath,
			INTERNET_OPEN_TYPE_PRECONFIG,
			0,0,0
	.if 	eax!=-1
		mov 	hNet,eax
		
		invoke 	lstrcpy,edi,offset szStaticUpdatePath
		
		invoke 	MakeRandomString,ADDR szUpdateBuff,10
		invoke 	lstrcat,edi,ADDR szUpdateBuff
		
		
		invoke 	SetLastError,0
		invoke 	InternetOpenUrl,
				hNet,
				edi,
				0,0,0,0
		mov 	hUrl,eax
		call 	GetLastError
		.if 	!eax
			
			; ------- get header for check version ------- ;
			valloc 	sizeof EXVDBINFO
			.if 	eax
				mov 	esi,eax
				
				push 	esi
				
				mov 	tmp,0
				
				.while 	tmp < sizeof EXVDBINFO
					lea 	eax,bufflen
					invoke 	InternetReadFile,hUrl,esi,sizeof EXVDBINFO,eax
					mov 	eax,bufflen
					add 	esi,eax
					add 	tmp,eax
					mov 	eax,tmp
				.endw
				
				pop 	esi
				
				; check
				cmp 	word ptr [esi],'DV'
				jne 	@noexvdb
				
				assume 	esi:ptr EXVDBINFO
				
				mov 	eax,dwRDYear
				mov 	edx,dwRDMonth
				mov 	ecx,dwRDDay
				
				cmp 	ax,[esi].wYear
				ja 		@noexvdb
				cmp 	dx,[esi].wMonth
				ja 		@noexvdb
				cmp 	cx,[esi].wDay
				ja 		@noexvdb
				
				.if 	ax==[esi].wYear && dx==[esi].wMonth && cx==[esi].wDay
					
					mov 	edi,InternetCloseHandle
					scall 	edi,hUrl
					scall 	edi,hNet
					
					jmp 	@noexvdb
				.endif
				
				; ------- save for f u ------- ;
				movzx 	eax,[esi].wYear
				mov 	[StcUpdateVersion.dwMajor],eax
				movzx 	eax,[esi].wMonth
				mov 	[StcUpdateVersion.dwMinor],eax
				movzx 	eax,[esi].wDay
				mov		[StcUpdateVersion.dwRevision],eax
				
				; ------- now download full ------- ;
				lea 	edi,szUpdatePathNow
				invoke 	lstrcpy,edi,offset szTempDir
				invoke 	TruePath,edi
				invoke 	lstrcat,edi,offset szMainUpdate
				invoke 	FileExist,edi
				.if 	eax
					invoke 	DeleteFile,edi
				.endif
				
				invoke 	CreateFile,edi,GENERIC_WRITE,FILE_SHARE_WRITE,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0
				.if 	eax!=-1
					mov 	hFile,eax
					
					invoke 	UpdateStatus,reparg("Download external database...")
					
					; ------- save header ------- ;
					invoke 	WriteFile,hFile,esi,sizeof EXVDBINFO,ADDR tmp,0
					
					; ------- get (download) exvdb body ------- ;
					vfree 	esi
					valloc 	sizeof SIAVDBv2
					.if 	eax
						mov 	esi,eax
						
						mov 	bufflen,sizeof SIAVDBv2
						.while 	bufflen
							
							invoke 	InternetReadFile,hUrl,esi,sizeof SIAVDBv2,ADDR bufflen
							invoke 	WriteFile,hFile,esi,bufflen,ADDR tmp,0
							
						.endw
						
						invoke 	UpdateStatus,reparg("Download completed")
						
						mov 	retv,1
						
					.else
						ViewError	hUpdateWnd,"Cannot allocate memory for static vdb body"
					.endif
					
					invoke 	CloseHandle,hFile
				.endif
				
				assume 	esi:nothing
				
		@noexvdb:
				vfree 	esi
			.else
				ViewError hUpdateWnd,"Cannot allocate memory for static update check"
			.endif
			
			invoke 	InternetCloseHandle,hUrl
		.endif
		
		
		invoke 	InternetCloseHandle,hNet
IFDEF 	DEBUG
	.else
		ViewError 0,"Cannot make connection for check vdb update."
ENDIF
	.endif
	
	mov 	eax,retv
	ret

CheckExVdb endp

align 16

OnLatestUpdate proc uses esi edi

	LOCAL 	buff[MAX_PATH+1]:BYTE
	LOCAL 	stime:SYSTEMTIME
	LOCAL 	vdbcnt:DWORD
	
	lea 	ebx,buff
	invoke MyZeroMemory,ebx,MAX_PATH
	invoke MyZeroMemory,ADDR stime,sizeof SYSTEMTIME
	
	invoke 	lstrcpy,ebx,offset szMyDir
	invoke 	TruePath,ebx
	invoke 	lstrcat,ebx,offset szAnupdCache
	
	; ------- check old version ------- ;
	invoke 	CreateFile,ebx,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	.if 	eax!=-1
		mov 	esi,eax
		
		valloc 	sizeof VERSIONINFO
		.if 	eax
			mov 	edi,eax
			
			invoke 	ReadFile,esi,edi,sizeof VERSIONINFO,offset brw,0
			.if 	eax
				
				invoke 	GetLocalTime,ADDR stime
				
				; ------- delete old cache ------- ;
				invoke 	CloseHandle,esi
				xor 	esi,esi
				invoke 	SetFileAttributes,ebx,FILE_ATTRIBUTE_NORMAL
				invoke 	DeleteFile,ebx 
				
				; ------- check prev version ------- ;
				mov 	eax,[edi.VERSIONINFO].dwMajor
				mov 	ecx,[edi.VERSIONINFO].dwMinor
				mov 	edx,[edi.VERSIONINFO].dwRevision
				.if 	(eax==VerMajor) && \
						(ecx==VerMinor) && \
						(edx==VerRevision) 
					jmp @vnok
				.else
					.if 	eax<VerMajor
						jmp @vok
					.endif
					.if 	ecx<VerMinor
						jmp @vok
					.endif
					.if 	edx<VerRevision
						jmp @vok
					.endif
				.endif
				
				jmp 	@vnok
				
@vok:
					call 	GetAllVdbCount		
						
					push 	eax
					push 	VerRevision
					push 	VerMinor
					push 	VerMajor
					push 	[edi.VERSIONINFO].dwRevision
					push 	[edi.VERSIONINFO].dwMinor
					push 	[edi.VERSIONINFO].dwMajor
					movzx 	eax,[stime.wYear]
					push 	eax
					movzx 	eax,[stime.wMonth]
					push 	eax
					movzx 	eax,[stime.wDay]
					push 	eax
					push 	offset szLatestUpdF
					push 	ebx
					call 	wsprintf
					add 	esp,4*12
					mov 	eax,MB_ICONINFORMATION
				jmp @F
@vnok:
					mov 	ebx,reparg("Update process failed, please contact the author for resolve this problem")
					mov 	eax,MB_ICONERROR
@@: 	
						
				invoke 	MessageBox,0,ebx,offset szAppName,eax
				
				
			.else
				ViewError	0,reparg("Cannot read file update cache")
			.endif
			
			
			vfree 	edi
		.else
			ViewError	0,offset szMemAllocError
		.endif
		
		.if esi
			invoke 	CloseHandle,esi
		.endif
	.endif

	ret
OnLatestUpdate endp

align 16

CreateUpdSnap proc uses esi ebx
	
	LOCAL 	lver:VERSIONINFO
	LOCAL 	buff[MAX_PATH+1]:BYTE
	
	invoke 	MyZeroMemory,ADDR lver,sizeof VERSIONINFO
	lea 	ebx,buff
	invoke 	MyZeroMemory,ebx,MAX_PATH
	
	invoke 	lstrcpy,ebx,offset szMyDir
	invoke 	TruePath,ebx
	invoke 	lstrcat,ebx,offset szAnupdCache
	
	invoke 	CreateFile,ebx,GENERIC_WRITE,FILE_SHARE_WRITE,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0
	.if 	eax!=-1
		mov 	esi,eax
		
		mov2 	[lver.dwMajor],VerMajor
		mov2 	[lver.dwMinor],VerMinor
		mov2 	[lver.dwRevision],VerRevision
		
		invoke 	WriteFile,esi,ADDR lver,sizeof VERSIONINFO,offset brw,0
		test 	eax,eax
		jz 		@err1
		invoke 	CloseHandle,esi
	.else
	@err1:
		ViewError	0,"Cannot create update file snapshot"
	.endif
	
	ret

CreateUpdSnap endp

szCantCvdb 	db 'Cannot change old "vdb.dat" file in ANSAV directory,',13,10
			db 'please make it accessible or delete it first manualy',13,10
			db 'then retry this static update.',0
szPleaseRestAGD db 'Update successfully, please restart ANSAV and Ansav Guard (if installed) to take effect.',0
szUpdFMask db "ANSAV static database (vdb.dat)",0,"*.dat",0,0

align 16

StaticOnlyOffline proc uses esi edi lParam:DWORD
	
	LOCAL 	ofn:OPENFILENAME
	LOCAL 	fname[MAX_PATH+1]:BYTE
	LOCAL 	buff[MAX_PATH+1]:BYTE
	LOCAL 	tmp[4]:BYTE
	LOCAL 	hFile:DWORD
	
	mov 	esi,MyZeroMemory
	mov 	esi,MyZeroMemory
	
	mov 	InUpdate,1
	
	lea 	eax,ofn
	scall 	esi,eax,sizeof OPENFILENAME
	lea 	eax,fname
	scall 	esi,eax,MAX_PATH
	lea 	edi,buff
	scall 	esi,edi,MAX_PATH
	
	mov 	[ofn.lStructSize],sizeof OPENFILENAME
	mov2 	[ofn.hwndOwner],hUpdateWnd
	mov2 	[ofn.hInstance],hInstance
	mov 	[ofn.nMaxFile],256
	lea 	eax,fname
	mov		[ofn.lpstrFile],eax
	mov 	[ofn.lpstrFilter],offset szUpdFMask
	invoke 	GetOpenFileName,ADDR ofn
	
	.if 	eax && fname[0]
		invoke 	lstrcpy,edi,offset szMyDir
		invoke 	TruePath,edi
		invoke 	lstrcat,edi,offset szVdbDat
		
		; ------- check for validation first ------- ;
		invoke 	CreateFile,ADDR fname,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
		.if 	eax!=-1
			mov 	hFile,eax
			invoke 	GetFileSize,hFile,0
			test 	eax,eax
			jz 		@errupdnf2
			
			xor 	ecx,ecx
			lea 	eax,tmp
			mov 	dword ptr [eax],ecx
			
			invoke 	ReadFile,hFile,eax,2,offset brw,0
			lea 	eax,tmp
			cmp 	word ptr [eax],'DV'
			jne 	@errupdnf2
			
			invoke 	SetFileAttributes,edi,FILE_ATTRIBUTE_NORMAL
			invoke 	DeleteFile,edi
			.if 	eax
				invoke 	CopyFile,ADDR fname,edi,0
				.if 	eax
					invoke 	MessageBox,hUpdateWnd,offset szPleaseRestAGD,offset szAppName,MB_OK
					invoke 	SetDlgItemText,hUpdateWnd,1004,reparg("FINISH")
					invoke 	UpdateStatus,offset szFinish
					mov 	InUpdate,0
				.else
					jmp	@cantvdb
				.endif
			.else
			@cantvdb:
				ViewError hUpdateWnd,offset szCantCvdb 
			.endif
		.else
			jmp @errupdnf
		.endif
	.endif
	
@endl:
	mov 	InUpdate,0
	invoke 	ExitThread,0
	
	ret
@errupdnf2:
	push 	hFile
	call 	CloseHandle
@errupdnf:
	ViewError	hUpdateWnd,"Update not found, or not available."
	jmp 	@endl

StaticOnlyOffline endp

align 16

AutomaticUpdateCheck proc uses esi
	
	; ------- seh installation ------- ;
	SehBegin 	_auc

	mov 	AutoUpdCheck,1
	
	call 	IsConnectedToInternet?
	test 	eax,eax
	jz 		@endl
	
	mov 	esi,AppendLogConsole
	
	scall 	esi,reparg("Check for available update...")
	
	; ------- build path main update ------- ;
	invoke 	lstrcpy,offset szUpdatePathNow,offset szHeaderDld
	invoke 	MakeRandomString,ADDR szUpdateBuff,10
	invoke 	lstrcat,offset szUpdatePathNow,ADDR szUpdateBuff
	
	call 	CheckUpdate
	.if 	eax
		scall 	esi,reparg("Found new update!")
		.while 	InScanning
			invoke 	Sleep,500
		.endw
		
		invoke 	IsWindowVisible,hMainWnd
		test 	eax,eax
		jz		@endl
		
		invoke 	MessageBox,hMainWnd,reparg("New update available!, do you want ANSAV to update now?"), \
				offset szAppName,MB_YESNO or MB_ICONQUESTION
		.if 	eax==IDYES
			mov 	UpdateReady,eax
			
			.while 	InScanning
				invoke 	Sleep,500
			.endw
			
			mov 	AutoUpdCheck,0
			invoke 	DialogBoxParam,hInstance,IDD_UPDATE,hMainWnd,UpdateDlgProc,0
			
		.endif
	.else
		scall 	esi,reparg("No update available at this time")
	.endif
	
	scall 	esi,reparg("Auto update check finished")
	
@endl:

	; ------- seh trapper ------- ;
	SehTrap 	_auc
		ErrorDump 	"AutomaticUpdateCheck",offset AutomaticUpdateCheck,offset szUpdateAsm
	SehEnd 		_auc

	xor 	eax,eax
	mov 	AutoUpdCheck,eax
	mov 	hAutUpdCheckThread,eax
	invoke 	ExitThread,eax
	ret

AutomaticUpdateCheck endp

