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

;### SEE - TODO9: ###

;-------------------------------------- Config.asm ----------------------------------------;
	IDC_EDIT_LEVELINFO	equ 1012
.data?
	tci 	TC_ITEM<>
	hConfigWnd	dd ?
	hConfigTab	dd ?
	hConfigSlider dd ?
	NeedRestartAnsav dd ?
	NeedRestartComputer dd ?
	ResidentTypeChanged dd ?
	lp_1042Proc dd ?
.data
	szLevel1Info	db "LOW SCAN",13,10
					db 13,10
					db "In this level of scan, ANSAV will scan file using level 1 (generic) and "
					db "level 2 (database method), "
					db "that only check file uses generic detection trick, like fake extention "
					db "or double extention in the file name eg. '.doc.exe'. and uses "
					db "internal ansav database. This option "
					db "not recomended, because no heuristic here. So, this imposible "
					db "to detect for new variant threat as ansav not have database for it. ",13,10
					db "But this option can make scan process more faster than other higher "
					db "level of scan method.",0
	szLevel2Info	db "MEDIUM SCAN",13,10
					db 13,10
					db "In this level of scan, ANSAV will scan file using level 3. Standard ANSAV heuristic, "
					db "that can handle for new farious of threat that have some characteristic "
					db "with some threat in internal database of ANSAV.",13,10
					db "So new variant of virus has made with old method, can be handled with "
					db "this scan level.",13,10
					db "In this level, ANSAV uses Standard heuristic that already used by old ANSAV +E "
					db "This option is recomended for keep against from new variant threat.",0
	szLevel3Info	db "HARDCORE SCAN",13,10
					db 13,10
					db "In this level of scan, ANSAV will scan file using level 4, "
					db "That not only scan for threat, but also detect for bad PE structure. "
					db "for example ANSAV will suspect the file that contains some destructive code "
					db "or bad image, corrupted header and some bad packer that have usualy used "
					db "by malware maker to pack her virus or trojan. So, some threat that have encrypted "
					db "code, polymorphic and mutation engine will be detected as suspect.",13,10
					db "But uses this option can make false alarm for some file that have bad PE header. ",13,10
					db "This option not available in old ANSAV +E, "
					db "and very recomended for user that can handle correctly, but is more slower "
					db "than other.",0 
	szActive	db "[ ACTIVE ]",0
	szInactive	db "[ NOT ACTIVE ]",0
	szMustInstall	db 'You must install ANSAV first to your computer before use this feature.',13,10
					db 'To install ANSAV, just click "Install Ansav" in "Help" menu, and follow the instruction.',0
	szProtectedMutex db "__protected__",0
.code

align 16

ConfigSlderSetPos proc uses edi esi ebx pos:DWORD
	
	mov 	esi,SetDlgItemText
	mov 	edi,hConfigWnd
	mov 	ebx,IDC_EDIT_LEVELINFO
	
	mov 	eax,pos
	.if 	eax == 1
		lea 	eax,szLevel3Info
		scall 	esi,edi,ebx,eax 
	.elseif 	eax == 2
		lea 	eax,szLevel2Info
		scall 	esi,edi,ebx,eax 
	.elseif 	eax == 3
		lea 	eax,szLevel1Info
		scall 	esi,edi,ebx,eax 
	.endif
	ret

ConfigSlderSetPos endp

align 16

ConfigPage1Show proc uses edi esi ebx s:DWORD
	
	mov 	esi,GetDlgItem
	mov 	ebx,ShowWindow
	mov 	edi,hConfigWnd
	
	push 	ebp
	mov 	ebp,s
	
	
	scall 	esi,edi,1003
	scall 	ebx,eax,ebp
	scall 	esi,edi,1004
	scall 	ebx,eax,ebp
	scall 	esi,edi,1005
	scall 	ebx,eax,ebp
	scall 	esi,edi,1006
	scall 	ebx,eax,ebp
	scall 	esi,edi,1007
	scall 	ebx,eax,ebp
	scall 	esi,edi,1009
	scall 	ebx,eax,ebp
	scall 	esi,edi,1011
	scall 	ebx,eax,ebp
	scall 	esi,edi,1012
	scall 	ebx,eax,ebp
	
	pop 	ebp
	ret

ConfigPage1Show endp

align 16

ConfigPage3Show proc uses edi esi ebx s:DWORD
	
	mov 	esi,GetDlgItem
	mov 	ebx,ShowWindow
	mov 	edi,hConfigWnd
	
	push 	ebp
	mov 	ebp,s
	
	scall 	esi,edi,1017
	scall 	ebx,eax,ebp
	scall 	esi,edi,1018
	scall 	ebx,eax,ebp
	scall 	esi,edi,1019
	scall 	ebx,eax,ebp
	scall 	esi,edi,1014
	scall 	ebx,eax,ebp
	scall 	esi,edi,1015
	scall 	ebx,eax,ebp
	scall 	esi,edi,1016
	scall 	ebx,eax,ebp
	scall 	esi,edi,1020
	scall 	ebx,eax,ebp
	
	invoke 	IsDlgButtonChecked,hConfigWnd,1020
	.if 	eax
		;call 	IsAnsavGuardActive?
		.if 	!AnsavGuardActive
			invoke 	GetDlgItem,hConfigWnd,1021
			scall 	ebx,eax,ebp
		.else
			jmp @F
		.endif
	.else
	@@:
		push 	EnableAngd
		call 	ConfigResidentControl
		invoke 	GetDlgItem,hConfigWnd,1021
		scall 	ebx,eax,0
	.endif
	
	pop 	ebp
	ret

ConfigPage3Show endp

align 16

ConfigPage2Show proc uses edi esi ebx s:DWORD
	
	mov 	esi,GetDlgItem
	mov 	ebx,ShowWindow
	mov 	edi,hConfigWnd
	push 	ebp
	mov 	ebp,s
	scall 	esi,edi,1022
	scall 	ebx,eax,ebp
	scall 	esi,edi,1023
	scall 	ebx,eax,ebp
	scall 	esi,edi,1024
	scall 	ebx,eax,ebp
	scall 	esi,edi,1025
	scall 	ebx,eax,ebp
	scall 	esi,edi,1026
	scall 	ebx,eax,ebp
	scall 	esi,edi,1027
	scall 	ebx,eax,ebp
	scall 	esi,edi,1028
	scall 	ebx,eax,ebp
	scall 	esi,edi,1029
	scall 	ebx,eax,ebp
	scall 	esi,edi,1030
	scall 	ebx,eax,ebp
	scall 	esi,edi,1031
	scall 	ebx,eax,ebp
	scall 	esi,edi,1032
	scall 	ebx,eax,ebp
	scall 	esi,edi,1033
	scall 	ebx,eax,ebp
	scall 	esi,edi,1035
	scall 	ebx,eax,ebp
	scall 	esi,edi,1050
	scall 	ebx,eax,ebp
	pop 	ebp
	ret

ConfigPage2Show endp

align 16

ConfigResidentControl proc uses edi esi ebx s:DWORD
	
	mov 	esi,GetDlgItem
	mov 	ebx,EnableWindow
	mov 	edi,hConfigWnd
	push 	ebp
	mov 	ebp,s
	scall 	esi,edi,1017
	scall 	ebx,eax,ebp
	scall 	esi,edi,1018
	scall 	ebx,eax,ebp
	scall 	esi,edi,1019
	scall 	ebx,eax,ebp
	scall 	esi,edi,1014
	scall 	ebx,eax,ebp
	scall 	esi,edi,1015
	scall 	ebx,eax,ebp
	scall 	esi,edi,1016
	scall 	ebx,eax,ebp
	pop 	ebp
	ret

ConfigResidentControl endp

align 16

SetConfigControlState proc uses ebx esi edi
	
	mov 	ResidentTypeChanged,0
	mov		NeedRestartAnsav,0
	mov 	NeedRestartComputer,0
	mov 	Uninstall,0
	
	mov 	esi,hConfigWnd
	lea 	edi,szInactive
	
	invoke 	SendMessage,hConfigSlider,TBM_SETPOS,1,1
	invoke 	SetDlgItemText,esi,IDC_EDIT_LEVELINFO,addr szLevel3Info
	
	invoke 	GetDlgItem,esi,1021
	invoke 	ShowWindow,eax,SW_HIDE
	invoke 	ConfigResidentControl,EnableAngd
	invoke 	CheckDlgButton,esi,1020,BST_UNCHECKED
	
	invoke 	SetDlgItemText,esi,1015,edi
	
	mov 	ebx,SetDlgItemText
	call 	IsAnsavGuardActive?
	.if 	!eax
		scall 	ebx,esi,1016,offset szActivate
		scall 	ebx,esi,1015,edi
	.else
		scall 	ebx,esi,1016,offset szStop
		scall 	ebx,esi,1015,offset szActive
	.endif

	push 	0
	call 	LoadConfig
	
	invoke 	GetDlgItem,hConfigWnd,1037
	invoke 	EnableWindow,eax,EnableArchiveScan
	invoke 	GetDlgItem,hConfigWnd,1038
	invoke 	EnableWindow,eax,EnableArchiveScan	
	
	ret

SetConfigControlState endp

align 16

EnableConfigControl proc uses ebx esi lState:DWORD
	
	mov 	ebx,GetDlgItem
	mov 	esi,EnableWindow
	
	scall 	ebx,hConfigWnd,1016
	scall 	esi,eax,lState
	scall 	ebx,hConfigWnd,1008
	scall 	esi,eax,lState
	scall 	ebx,hConfigWnd,1013
	scall 	esi,eax,lState
	scall 	ebx,hConfigWnd,1010
	scall 	esi,eax,lState
	scall 	ebx,hConfigWnd,1001
	scall 	esi,eax,lState	
	scall 	esi,hConfigWnd,lState
	
	ret

EnableConfigControl endp

align 16


ConfigPage5Show proc uses ebx esi edi lState:DWORD
	
	mov 	ebx,GetDlgItem
	mov 	esi,ShowWindow
	mov 	edi,hConfigWnd
	
	scall 	ebx,edi,1039
	scall 	esi,eax,lState
	scall 	ebx,edi,1036
	scall 	esi,eax,lState
	scall 	ebx,edi,1037
	scall 	esi,eax,lState
	scall 	ebx,edi,1038
	scall 	esi,eax,lState
	
	scall 	ebx,edi,1044
	scall 	esi,eax,lState
	scall 	ebx,edi,1045
	scall 	esi,eax,lState
	scall 	ebx,edi,1046
	scall 	esi,eax,lState
	scall 	ebx,edi,1047
	scall 	esi,eax,lState
	scall 	ebx,edi,1048
	scall 	esi,eax,lState
	scall 	ebx,edi,1049
	scall 	esi,eax,lState
	scall 	ebx,edi,1040
	scall 	esi,eax,lState
	scall 	ebx,edi,1041
	scall 	esi,eax,lState
	scall 	ebx,edi,1042
	scall 	esi,eax,lState
	scall 	ebx,edi,1043
	scall 	esi,eax,lState

		
	ret

ConfigPage5Show endp

align 16

IsAnsavGuardActive? proc
	
	invoke 	OpenMutex,1,0,ADDR szProtectedMutex
	.if 	eax
		invoke 	CloseHandle,eax
		return_1
	.endif
	return_0
	ret

IsAnsavGuardActive? endp


align 16

EnableDisableAG proc uses edi ebx esi lParam:DWORD
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	LOCAL 	lBuff2[MAX_PATH+1]:BYTE
	LOCAL 	TTL:DWORD
	LOCAL 	lsi:STARTUPINFO
	LOCAL 	lpi:PROCESS_INFORMATION
	LOCAL 	retv:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__edag
	
	
	mov 	retv,0
	
	mov 	edi,MyZeroMemory
	mov 	esi,hConfigWnd
	
	lea 	eax,lsi
	scall 	edi,eax,sizeof STARTUPINFO
	lea 	eax,lpi
	scall 	edi,eax,sizeof PROCESS_INFORMATION
	lea 	eax,lBuff
	scall 	edi,eax,MAX_PATH
	lea 	eax,lBuff2
	scall 	edi,eax,MAX_PATH

	cmp 	Uninstall,0
	ja 		@onlystopit
	
	cmp 	lParam,2
	je 		@onlystopit
	
	invoke 	SetDlgItemText,esi,1015,reparg("[ WAITING... ]")
	invoke 	GetDlgItemText,esi,1016,ADDR lBuff,30
	
	invoke 	EnableConfigControl,FALSE
	
	invoke 	lstrcmpi,ADDR lBuff,ADDR szStop
	.if 	zero?
@onlystopit:
		invoke 	AppendLogConsole,reparg("Try to disable Ansav Guard...")
		
		; ------- remove tray icon first ------- ;
		invoke 	FindWindow,offset szTrayClass,0
		.if 	!eax
			invoke 	AppendLogConsole,reparg("Can't find tray object")
		.endif
		invoke 	SendMessage,eax,WM_COMMAND,1024,0
		; -------------- ;
		
		invoke 	GetModuleHandle,ADDR szAnhookerPath

		.if 	eax
			invoke 	GetProcAddress,eax,ADDR sz__ret32
			.if 	eax
				scall 	eax,'STOP'	; <-- command service to stop work ;
			.endif
		.else
			ViewError 	esi,"Cannot make connection to service..."
			invoke 	IsAnsavGuardActive?
			.if 	eax
				invoke 	SetDlgItemText,esi,1015,ADDR szActive
				invoke 	SetDlgItemText,esi,1016,ADDR szStop
				invoke 	EnableConfigControl,TRUE
				SehPop
				mov 	eax,retv
				ret
			.endif
		.endif
		
		mov 	TTL,0; ------- WAIT ------- ;
		@lp:
		invoke 	GetModuleHandle,ADDR szAnhookerPath
		.if 	!eax
			.if 	!Uninstall
				invoke 	SetDlgItemText,esi,1015,ADDR szInactive
				invoke 	SetDlgItemText,esi,1016,ADDR szActivate
			.endif
			invoke 	AppendLogConsole,ADDR szSuccess
			mov 	retv,1
		.else
			invoke 	Sleep,500
			inc 	TTL
			cmp 	TTL,30
			jb		@lp
			
			call 	TryKillAnsavgd
			cmp 	TTL,40
			jb 		@lp
			
			jmp 	@failed
		.endif
	.else
		
		invoke 	lstrcmpi,ADDR lBuff,reparg("Activate")
		.if 	zero?
                                                    ; ------- ACTIVATE IT ------- ;
			invoke 	AppendLogConsole,reparg("Try to activate Ansav Guard...")
			
			push 	esi
			push 	edi
			
			invoke 	OpenSCManager,0,0,2
			mov 	esi,eax
			.if 	esi
				
				invoke 	OpenService,esi,offset szAnsavgd,SERVICE_START
				.if 	eax
					mov 	edi,eax
					invoke 	StartService,edi,0,0
					.if 	eax
						invoke 	SetDlgItemText,hConfigWnd,1015,ADDR szActive
						invoke 	SetDlgItemText,hConfigWnd,1016,ADDR szStop
						invoke 	AppendLogConsole,ADDR szSuccess
						invoke 	SetForegroundWindow,hConfigWnd
						mov 	AnsavGuardActive,1
					.else
						invoke 	CloseServiceHandle,edi
						invoke 	CloseServiceHandle,esi
						jmp @failed
					.endif
					invoke 	CloseServiceHandle,edi
				.endif
				invoke 	CloseServiceHandle,esi
			.endif
			
			pop 	edi
			pop 	esi
			
		.endif
	.endif
	.if 	!Uninstall
		invoke 	EnableConfigControl,TRUE
	.endif
	
	; ------- seh trapper ------- ;
	SehTrap 	__edag
		ErrorDump	"EnableDisableAG",offset EnableDisableAG,"Config.asm"
	SehEnd		__edag
	
	
	mov 	eax,retv
	ret
	
@failed:
	ViewError	esi,"Cannot make connection to service, service not respond."
@failed2:
	
	invoke 	lstrcpy,ADDR lBuff2,ADDR lBuff
	invoke 	lstrcat,ADDR lBuff2,reparg(" stop ansavgd")
	
	mov 	[lsi.lpTitle],reparg("Clean up...")
	invoke 	CreateProcess,ADDR lBuff,ADDR lBuff2,0,0,0,0,0,ADDR szWinDir,ADDR lsi,ADDR lpi
	.if 	!Uninstall
		invoke 	SetDlgItemText,esi,1015,ADDR szInactive
		invoke 	EnableConfigControl,TRUE
	.endif
	SehPop
	mov 	eax,retv
	ret
EnableDisableAG endp


align 16

.data
	szBecomeDonatour db \
		"Auto update is special feature only for ANSAV donatour or ANSAV community member. This case to prevent "
		db "bandwidth limit usage in update server.",13,10,13,10
		db "If You want to use this feature, please register first as ANSAV donatour or ANSAV community member.",13,10,13,10
		db "In community you can also study how to make security tool and learn some programming language "
		db "like VB, C, C++ and Assembly. Also how to build Plugins for ANSAV.",13,10,13,10
		db "for more information, contact : anvie_2194@yahoo.com",13,10,0
		
.code

align 16

ConfigDlgProc 	proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	
	mov 	eax,uMsg
	.if 	eax == WM_INITDIALOG
		
		m2m 	hConfigWnd,hWin
		
		.if 	TimeForBlind
			invoke 	SetWindowText,hWin,ADDR szAppName
		.endif
		
		invoke 	GetDlgItem,hWin,1001
		mov 	hConfigTab,eax
		call 	BuildTab
		
		invoke 	GetDlgItem,hWin,1004
		mov 	hConfigSlider,eax
		call 	BuildSlider
		
		call 	SetConfigControlState
		
		invoke 	GetDlgItem,hWin,1034
		invoke 	ShowWindow,eax,SW_HIDE
		
		invoke 	SetDlgItemText,hWin,1034,offset szBecomeDonatour
		
		invoke 	GetDlgItem,hWin,1042
		lea 	edx,_1042Proc
		invoke 	SetWindowLong,eax,GWL_WNDPROC,edx
		mov 	lp_1042Proc,eax
		
		invoke 	SetFocus,hWin
		
		
	.elseif 	eax == WM_CLOSE
@close:
		call 	SaveConfig
		call 	RenewConfigFlags
		invoke 	SetLastError,0
		invoke 	EndDialog,hWin,0
		
	.elseif 	eax == WM_COMMAND
		mov 	eax,wParam
		and 	eax,0FFFFh
		.if 	eax == 1008 	; <-- CANCEL ;
			invoke 	EndDialog,hWin,0
		.elseif 	eax == 1013
			jmp 	@close
		.elseif 	eax == 1010 		; <-- APPLY ;
			call 	SaveConfig
			call 	RenewConfigFlags
		.elseif 	eax == 1004
			invoke 	MessageBox,hWin,0,0,0
		.elseif 	eax == 1020 		; <-- ENABLE RESIDENT CHEKCBOX ;
			mov 	ResidentTypeChanged,1
			call 	EnableResident
		.elseif 	eax == 1033 ; NO PLUGINS COMMAND
			mov 	NeedRestartAnsav,1
		.elseif 	eax == 1039 ; ENABLE DISABLE ARCHIVE SCAN CHECKBOX
			invoke 	IsDlgButtonChecked,hConfigWnd,eax
			push 	esi
			mov 	esi,eax
			invoke 	GetDlgItem,hConfigWnd,1037
			invoke 	EnableWindow,eax,esi
			invoke 	GetDlgItem,hConfigWnd,1038
			invoke 	EnableWindow,eax,esi
			pop 	esi
		.elseif 	eax == 1016 	; <-- ACTIVE/DISABLE ANSAV GUARD ;
			invoke 	CreateThread,0,0,ADDR EnableDisableAG,0,0,ADDR brw
			invoke 	CloseHandle,eax
		.elseif 	eax==1018 || eax == 1019
			mov 	NeedRestartComputer,1
		.elseif 	eax==1041	; <-- LIMIT ARC SIZE TO SCAN ;
			invoke 	IsDlgButtonChecked,hWin,eax
			push 	eax
			invoke 	GetDlgItem,hWin,1042
			scall 	EnableWindow,eax
		.endif
	.elseif 	eax == WM_VSCROLL; ------- SCAN METHOD SCROLL ------- ;
		mov 	eax,[wParam]
		and 	eax,0FFFFh
		push 	esi	; <--;
		push 	ebx
		mov 	esi,SendMessage
		mov 	ebx,hConfigSlider
		.if 	eax == TB_THUMBTRACK or TB_THUMBPOSITION
			mov 	eax,[wParam]
			shr 	eax,16
			invoke 	ConfigSlderSetPos,eax
		.elseif 	eax == TB_LINEUP
			scall 	esi,ebx,TBM_GETPOS,0,0
			invoke 	ConfigSlderSetPos,eax
		.elseif 	eax == TB_LINEDOWN
			scall 	esi,ebx,TBM_GETPOS,0,0
			invoke 	ConfigSlderSetPos,eax
		.elseif 	eax == TB_TOP
			scall 	esi,ebx,TBM_GETPOS,0,0
			invoke 	ConfigSlderSetPos,eax
		.elseif 	eax == TB_BOTTOM
			scall 	esi,ebx,TBM_GETPOS,0,0
			invoke 	ConfigSlderSetPos,eax
		.elseif 	eax == TB_PAGEUP
			scall 	esi,ebx,TBM_GETPOS,0,0
			invoke 	ConfigSlderSetPos,eax
		.elseif 	eax == TB_PAGEDOWN
			scall 	esi,ebx,TBM_GETPOS,0,0
			invoke 	ConfigSlderSetPos,eax
		.endif
		pop 	ebx
		pop 	esi	; <--;
	.elseif 	eax == WM_NOTIFY
		mov 	edx,[lParam]
		mov 	eax,[edx.NMHDR].hwndFrom
		.if 	eax == hConfigTab
			mov 	eax,[edx.NMHDR].code
			.if 	eax ==TCN_SELCHANGE
				invoke 	SendMessage,hConfigTab,TCM_GETCURSEL,0,0
				push 	esi
				push 	edi
				push 	ebx
				mov 	esi,ConfigPage1Show
				mov 	edi,ConfigPage2Show
				mov 	ebx,ConfigPage3Show
				
				.if 	eax==0
					scall 	esi,TRUE
					scall 	edi,FALSE
					scall 	ebx,FALSE
					invoke 	ConfigPage5Show,FALSE
				.elseif 	eax == 1
					scall 	esi,FALSE
					scall 	edi,TRUE
					scall 	ebx,FALSE
					invoke 	ConfigPage5Show,FALSE
				.elseif 	eax == 2
					scall 	esi,FALSE
					scall 	edi,FALSE
					scall 	ebx,TRUE
					invoke 	ConfigPage5Show,FALSE
				.elseif 	eax == 3
					scall 	esi,FALSE
					scall 	edi,FALSE
					scall 	ebx,FALSE
					invoke 	ConfigPage5Show,TRUE
				.elseif 	eax == 4
					scall 	esi,FALSE
					scall 	edi,FALSE
					scall 	ebx,FALSE
					invoke 	ConfigPage5Show,FALSE
				.endif
				pop 	ebx
				pop 	edi
				pop 	esi
			.endif
		.endif
	.endif
	
	xor 	eax,eax
	ret

BuildTab:
	push 	ebx
	push 	esi
	
	
	mov 	ebx,SendMessage
	mov 	esi,hConfigTab
	
	mov 	[tci.imask],TCIF_TEXT
	mov 	[tci.cchTextMax],MAX_PATH
	mov 	[tci.pszText],reparg("Scan method")
	lea 	eax,tci
	scall 	ebx,esi,TCM_INSERTITEM,0,eax
	mov 	[tci.pszText],reparg("Settings")
	lea 	eax,tci
	scall 	ebx,esi,TCM_INSERTITEM,1,eax
	mov 	[tci.pszText],reparg("Resident")
	lea 	eax,tci
	scall 	ebx,esi,TCM_INSERTITEM,2,eax
	mov 	[tci.pszText],reparg("Archives")
	lea 	eax,tci
	scall 	ebx,esi,TCM_INSERTITEM,3,eax
	
	pop 	esi
	pop 	ebx
	
	invoke 	ConfigPage1Show,TRUE
	invoke 	ConfigPage2Show,FALSE
	invoke 	ConfigPage3Show,FALSE
	invoke 	ConfigPage5Show,FALSE
	retn
BuildSlider:
	invoke 	SendMessage,hConfigSlider,TBM_SETRANGEMIN,FALSE,1
	invoke 	SendMessage,hConfigSlider,TBM_SETRANGEMAX,FALSE,3
	retn
EnableResident:

	invoke 	IsAlreadyInstalled?
	test 	eax,eax
	jnz		@F
		invoke 	MessageBox,hWin,
			ADDR szMustInstall,
			ADDR szAppName,MB_OK
		invoke 	CheckDlgButton,hWin,1020,BST_UNCHECKED
		retn
	@@:

	push 	ebx
	mov 	ebx,1
	invoke 	IsDlgButtonChecked,hWin,1020
	push 	eax
	.if 	!eax		
		invoke 	IsAnsavGuardActive?
		.if 	eax
			invoke 	CheckDlgButton,hWin,1020,BST_CHECKED
			invoke 	MessageBox,hConfigWnd,
				reparg("You wanted to disable Ansav Guard feature, please stop it first."),
				ADDR szAppName,MB_OK
			mov 	dword ptr [esp],1
			
		.endif
		mov 	ebx,0
	.endif
	invoke 	GetDlgItem,hWin,1021
	mov 	edx,eax
	push 	ebx
	push 	edx
	call 	ShowWindow
	call 	ConfigResidentControl
	pop 	ebx
	retn

ConfigDlgProc endp

align 16

StartConfigDlg proc
	
	invoke 	AppendLogConsole,reparg("Starting config dialog...")
	invoke 	DialogBoxParam,hInstance,IDD_CONFIGURATION,hMainWnd,ADDR ConfigDlgProc,0
	invoke 	GetLastError
	ret

StartConfigDlg endp

align 16

SetConfigItem proc uses edi lpKey:DWORD,Value:DWORD
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	
	lea 	edi,lBuff
	invoke 	MyZeroMemory,edi,MAX_PATH
	invoke 	wsprintf,edi,ADDR szdTosF,Value
	invoke 	WritePrivateProfileString,ADDR szAnsavName,lpKey,edi,ADDR szAnsavIniPath
	ret

SetConfigItem endp

align 16

GetConfigItem proc lpKey:DWORD
	
	invoke 	GetPrivateProfileInt,ADDR szAnsavName,lpKey,0,ADDR szAnsavIniPath
	ret

GetConfigItem endp

align 16

.data?
	szSaveConfigBuff db MAX_PATH+1 dup(?)
.data
	; ------- SZ ------- ;
	szScanLevel db "SCANLEVEL",0
	szNoBipServ db "NOBIPSERV",0
	szNoDetcSound db "NODETCSND",0
	szMainScanBtn	db "MAINSCNBTN",0
	szNoFQC		db "NOFQC",0
	szNoScanMem	db "NOSCANMEM",0
	szShowResult db "SHOWRESULT",0
	szNoActConfrm db "NOACTCONF",0
	szShowLog	db "SHOWLOG",0
	szNoPlugins db "NOPLUG",0
	szEnableAngd db "ENAGD",0
	szStealthMode db "STEALTH",0
	szEnableArchiveScan db "ENARCSCAN",0
	szLimitArcS db "LIMITARCS",0
	szLimitArcSizeAt db "LIMITSARCAT",0
	szDontAskDelSusp db "DONTASKDELSUSP",0
	szZIP db "ZIP",0
	szJAR db "JAR",0
	szRAR db "RAR",0
.code

SaveConfig proc uses esi edi ebx 

	; ------- seh installation ------- ;
	SehBegin 	__sc

	invoke 	AppendLogConsole,reparg("Saving configuration...")

	.if 	NeedRestartComputer
		invoke 	MessageBox,hConfigWnd,reparg("Some setting configuration need to restart computer."),
			ADDR szAppName,MB_OK
		mov 	NeedRestartComputer,0
	.else
		.if 	NeedRestartAnsav
			invoke 	MessageBox,hConfigWnd,reparg("Some setting configuration need to restart ANSAV."),
				ADDR szAppName,MB_OK
			mov 	NeedRestartAnsav,0
		.endif
	.endif

	mov 	esi,IsDlgButtonChecked
	mov 	ebx,hConfigWnd
	mov 	edi,SetConfigItem
	
	invoke 	SendMessage,hConfigSlider, TBM_GETPOS,0,0
	.if 	eax == 1
		mov 	eax,3
	.elseif 	eax == 2
		mov 	eax,2
	.elseif 	eax == 3
		xor 	eax,eax
		inc 	eax
	.else
		mov 	eax,3
	.endif
	mov 	ScanLevel,eax
	scall 	edi,offset szScanLevel,eax
	
	; ------- MAIN SCAN BUTTON ------- ;
	scall 	esi,ebx,1023
	.if 	eax
		mov 	MainScanButton,1
		scall 	edi,offset szMainScanBtn,1
	.endif
	scall 	esi,ebx,1024
	.if 	eax
		mov 	MainScanButton,2
		scall 	edi,offset szMainScanBtn,2
	.endif
	scall 	esi,ebx,1025
	.if 	eax
		mov 	MainScanButton,3
		scall 	edi,offset szMainScanBtn,3
	.endif
	
	; ------- BIP SERV ------- ;
	scall 	esi,ebx,1004
	mov 	NoBipServ,eax
	scall 	edi,offset szNoBipServ,eax
	
	; ------- NO COMPRESS FQ ------- ;
	scall 	esi,ebx,1032
	mov 	NoFQC,eax
	scall 	edi,offset szNoFQC,eax
	
	; ------- NO SCAN MEM ------- ;
	scall 	esi,ebx,1027
	mov 	NoScanMem,eax
	scall 	edi,offset szNoScanMem,eax
	
	; ------- SHOW RESULT ------- ;
	scall 	esi,ebx,1028
	mov 	ShowResult,eax
	scall 	edi,offset szShowResult,eax
	
	; ------- DON'T CONFIRM ACTION ------- ;
	scall 	esi,ebx,1029
	mov 	NoActConfirm,eax
	scall 	edi,offset szNoActConfrm,eax
	
	; ------- SHOW LOG CONSOLE ------- ;
	scall 	esi,ebx,1030
	mov 	ShowLog,eax
	scall 	edi,offset szShowLog,eax
	
	; ------- NO PLUGINS ------- ;
	scall 	esi,ebx,1033
	mov 	NoPlugins,eax
	scall 	edi,offset szNoPlugins,eax
	
	; ------- ENABLE ANGD ------- ;
	scall 	esi,ebx,1020
	mov 	EnableAngd,eax
	scall 	edi,offset szEnableAngd,eax	
	
	; ------- dont make bip if service start ------- ;
	scall 	esi,ebx,1018
	scall 	edi,offset szNoBipServ,eax	
	
	; ------- dont make bip if detected ------- ;
	scall 	esi,ebx,1019
	scall 	edi,offset szNoDetcSound,eax	
	
	; ------- stealth mode ------- ;
	scall 	esi,ebx,1035
	mov 	StealthMode,eax
	scall 	edi,offset szStealthMode,eax
	
	; ------- enable archive scan ------- ;
	scall 	esi,ebx,1039
	mov 	EnableArchiveScan,eax
	scall 	edi,offset szEnableArchiveScan,eax
	
	; ------- ZIP ------- ;
	scall 	esi,ebx,1037
	mov 	ZIP,eax
	scall 	edi,offset szZIP,eax
	
	; ------- JAR ------- ;
	scall 	esi,ebx,1038
	mov 	JAR,eax
	scall 	edi,offset szJAR,eax
	
	; ------- LIMIT ARC SIZE TO SCAN ------- ;
	scall 	esi,ebx,1041
	mov 	LimitArcSize,eax
	scall 	edi,offset szLimitArcS,eax
	
	; ------- DON'T ASK DELETE SUSPECT ------- ;
	scall 	esi,ebx,1050
	mov 	DontAskDelSusp,eax
	scall 	edi,offset szDontAskDelSusp,eax
	
	invoke 	GetDlgItemText,hConfigWnd,1042,offset szSaveConfigBuff,MAX_PATH
	push 	offset szSaveConfigBuff
	call 	atodw
	.if 	LimitArcSize
		push 	eax
		
		xor 	edx,edx
		mov 	ecx,1000000
		mul 	ecx
		mov 	LimitArcSizeTS,eax
		
		pop 	eax
	.else
		mov 	LimitArcSizeTS,0
	.endif
	scall 	edi,offset szLimitArcSizeAt,eax
	
	.if 	!EnableArchiveScan
		.if 	ArcReady
			invoke 	FreeLibrary,hArcMod
			mov 	ArcReady,0
			mov 	hArcMod,0
		.endif
	.else
		call 	ArcInit
		mov 	ArcReady,eax
	.endif
	
	; ------- SERVICE START TYPE ------- ;
	.if 	ResidentTypeChanged
		scall 	esi,ebx,1020
		.if 	eax
			invoke 	SetServiceStartType,SERVICE_AUTO_START
		.else
			invoke 	SetServiceStartType,SERVICE_DEMAND_START
		.endif
	.endif
	
	invoke 	AppendLogConsole,reparg("Configuration saved.")
	
	; ------- seh trapper ------- ;
	SehTrap 	__sc
		ErrorDump	"SaveConfig",offset SaveConfig,"Config.asm"
	SehEnd 		__sc
	
	ret

SaveConfig endp

align 16

LoadConfig proc uses edi esi ebx lParam:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__lc
	
	.if 	!lParam
		invoke 	AppendLogConsole,reparg("Loading configuration...")
	.endif
	invoke 	GetConfigItem,ADDR szScanLevel
	mov 	ScanLevel,eax
	.if 	eax == 1
		mov 	eax,3
	.elseif 	eax == 2
		mov 	eax,2
	.elseif 	eax == 3
		xor 	eax,eax
		inc 	eax
	.else
		mov 	eax,3
		mov 	ScanLevel,eax
	.endif
	
	.if 	!lParam
		invoke 	SendMessage,hConfigSlider,TBM_SETPOS,eax,eax
	.endif
	
	mov 	esi,GetConfigItem
	mov 	ebx,hConfigWnd
	mov 	edi,CheckDlgButton
	
	scall 	esi,offset  szMainScanBtn
	mov 	MainScanButton,eax
	.if 	eax
		add 	eax,1022
		scall 	edi,ebx,eax,BST_CHECKED
	.else
		scall 	edi,ebx,1023,BST_CHECKED
	.endif
	; ------- BIP SERVICE ------- ;
	scall 	esi,offset szNoBipServ
	mov 	NoBipServ,eax
	scall 	edi,ebx,1004,eax
	
	; ------- NO COMPRESS FQ ------- ;
	scall 	esi,offset szNoFQC
	mov 	NoFQC,eax
	scall 	edi,ebx,1032,eax
	
	; ------- NO SCAN MEM ------- ;
	scall 	esi,offset szNoScanMem
	mov 	NoScanMem,eax
	scall 	edi,ebx,1027,eax
	
	; ------- SHOW RESULT ------- ;
	scall 	esi,offset szShowResult
	mov 	ShowResult,eax
	scall 	edi,ebx,1028,eax
	
	; ------- DON'T CONFIRM ACTION ------- ;
	scall 	esi,offset szNoActConfrm
	mov 	NoActConfirm,eax
	scall 	edi,ebx,1029,eax
	
	; ------- SHOW LOG CONSOLE ------- ;
	scall 	esi,offset szShowLog
	mov 	ShowLog,eax
	scall 	edi,ebx,1030,eax
	
	; ------- NO PLUGINS ------- ;
	scall 	esi,offset szNoPlugins
	mov 	NoPlugins,eax
	scall 	edi,ebx,1033,eax
	
	; ------- dont make bip if service start ------- ;
	scall 	esi,offset szNoBipServ
	scall 	edi,ebx,1018,eax
	
	; ------- dont make bip if detected ------- ;
	scall 	esi,offset szNoDetcSound
	scall 	edi,ebx,1019,eax
	
	; ------- stealth mode ------- ;
	scall 	esi,offset szStealthMode
	mov 	StealthMode,eax
	scall 	edi,ebx,1035,eax
	
	; ------- enable archive scan ------- ;
	scall 	esi,offset szEnableArchiveScan
	mov 	EnableArchiveScan,eax
	scall 	edi,ebx,1039,eax

	; ------- ZIP ------- ;
	scall 	esi,offset szZIP
	mov 	ZIP,eax
	scall 	edi,ebx,1037,eax
	
	; ------- JAR ------- ;
	scall 	esi,offset szJAR
	mov 	JAR,eax
	scall 	edi,ebx,1038,eax
	
	; ------- LIMIT ARC SIZE TO SCAN ------- ;
	scall 	esi,offset szLimitArcS
	mov 	LimitArcSize,eax
	.if !lParam
		push 	eax
		scall 	edi,ebx,1041,eax
		invoke 	GetDlgItem,hConfigWnd,1042
		scall 	EnableWindow,eax
	.endif
	
	scall 	esi,offset szLimitArcSizeAt
	.if 	LimitArcSize		
		push 	eax
		
		xor 	edx,edx
		mov 	ecx,1000000
		mul 	ecx
		mov 	LimitArcSizeTS,eax
		
		pop 	eax
	.else
		mov 	LimitArcSizeTS,0
	.endif
	.if  !lParam
		invoke 	wsprintf,offset szSaveConfigBuff,offset szdTosF,eax
		invoke 	GetDlgItem,hConfigWnd,1042
		invoke 	SetDlgItemText,hConfigWnd,1042,offset szSaveConfigBuff
	.endif
	
	; ------- DON'T ASK DELETE SUSPECT ------- ;
	scall 	esi,offset szDontAskDelSusp
	mov 	DontAskDelSusp,eax
	scall 	edi,ebx,1050,eax

	
	; ------- ENABLE ANGD ------- ;
	scall 	esi,offset szEnableAngd
	mov 	EnableAngd,eax
	scall 	edi,ebx,1020,eax
	call 	IsAnsavGuardActive?
	.if		!eax
		call 	IsAlreadyInstalled?
		.if 	!eax
			mov 	EnableAngd,eax
			scall 	edi,ebx,1020,eax
		.endif
	.else
		mov 	EnableAngd,1
		mov 	AnsavGuardActive,1
		scall 	edi,ebx,1020,eax
		invoke 	SetConfigItem,offset szEnableAngd,eax
	.endif
	
	.if 	!StealthMode
		call 	CleanupSteTmp
	.endif
	
	invoke 	AppendLogConsole,reparg("Configuration loaded.")
	
	; ------- seh trapper ------- ;
	SehTrap 	__lc
		ErrorDump 	"LoadConfig",offset LoadConfig,"Config.asm"
	SehEnd 		__lc
	
	ret

LoadConfig endp

align 16

RenewConfigFlags proc uses esi edi
	
	
	; ------- seh installation ------- ;
	SehBegin	__rcf
	
	.if 	StealthMode
		; ------- try uses stealth ------- ;
		.if 	hStealthHookMod
			SehPop
			ret
		.endif
		mov 	hStealthfMap,0
		mov 	hStealthHook,0
		mov 	hStealthHookMod,0
		mov 	hStealthmMap,0
		call 	Stealth
		.if 	!eax
			ViewError 	hMainWnd,"Stealth mode cannot activated, stealth mode=off"
		.else
			.if 	!TimeForBlind
				lea 	esi,szAppName
				
				strlen esi
				
				mov 	edi,esi
				mov 	ecx,eax
				sub 	ecx,3
				@@:
					dec 	ecx
					jecxz	@F
					cmp 	dword ptr [edi+ecx],']htl'
					jne 	@B
					jmp 	@nx
				@@:
				invoke 	lstrcat,esi,reparg(" - [stealth]")
				invoke 	SetWindowText,hMainWnd,esi
				@nx:
			.endif
		.endif
	.else
		call 	UnStealth
	.endif
	
	; ------- seh trapper ------- ;
	SehTrap 	__rcf
		ErrorDump 	"RenewConfigFlags",offset RenewConfigFlags,"config.asm"
	SehEnd 		__rcf
	ret

RenewConfigFlags endp

align 16

_1042Proc proc	hCtl:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	
	mov 	eax,uMsg
	.if 	eax == WM_CHAR
		mov 	eax,wParam
		.if 	eax!=8	; <-- back space ;
			.if 	eax < 48 || eax > 57
				mov 	[wParam],0
			.endif
		.endif
		push 	eax
		invoke 	GetWindowTextLength,hCtl
		.if 	eax > 5 && dword ptr [esp] != 8
			mov 	[wParam],0
		.endif
		add 	esp,4
	.endif
	invoke 	CallWindowProc,lp_1042Proc,hCtl,uMsg,wParam,lParam
	ret

_1042Proc endp
