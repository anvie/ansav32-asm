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


; ------- AnvdbDlg.asm ------- ;

.data?
	
	hAnvdb				dd ?
	hAnvdbPB			dd ?
	StopBuildVdb		dd ?
	hAnvdbList			dd ?
	hAnvdbBuilder		dd ?
	
	hAnvdbCmdReload		dd ?
	hAnvdbCmdClose		dd ?
	lpListWndProc		dd ?

.const

ANVDB_POPULATE_LIST equ 1
ANVDB_SAVE_LIST 	equ 2

IDD_ANVDBBP			equ 	1004 
IDC_ANVDB_CLOSE		equ 	1005
IDC_ANVDBBP_CANCEL 	equ 	1005
IDC_TXT_THREATCNT	equ 	1016
IDC_ANVDB_RELOAD 	equ 	1014

IDC_TXT_THNAME		equ 1018
IDC_TXT_THTYPE 		equ 1007
IDC_TXT_FILETYPE	equ 1019
IDC_TXT_RISK		equ 1020
IDC_TXT_ORIGIN 		equ 1021
IDC_TXT_AUTHOR		equ 1022

.data
	szThreatTxtF 	db "; AUTO GENERATED FILE ",13,10
				 	db "; All known threats in ANSAV version %d.%d.%d",13,10
				 	db "; Last Database Update : %d.%d.%d (include external)",13,10
				 	db "; Known Threats        : %d threats",13,10
				 	db ";",13,10
				 	db "; http://www.ansav.com",13,10,13,10
				 	db 13,10,0  
	
.code

align 16

AnvdbListProc proc uses esi hCtl:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	LOCAL 	lIndex:DWORD
	LOCAL 	lType:DWORD
	LOCAL 	lBuff[256+1]:BYTE
	LOCAL 	exvdb:DWORD

	mov 	eax,uMsg
	.if 	eax == WM_LBUTTONUP || eax == WM_KEYUP
		
		; ------- seh installation ------- ;
		SehBegin 	__avlp
		
		push 	esi
		
		invoke 	SendMessage,hCtl,LB_GETCURSEL,0,0
		mov 	lIndex,eax
		
		mov 	exvdb,0
		xchg 	ecx,eax
		assume 	esi:ptr SVDBv2
		; ------- Search jump ------- ;
		lea 	esi,AnsavVDBv2
		test 	ecx,ecx
		jz 		@okay
		@lp:
			add 	esi,sizeof SVDBv2
			lea 	eax,[esi].szThreatName
			invoke 	IsSuspName,eax
			.if 	eax
				inc 	ecx
			.endif
			cmp 	byte ptr [esi],0
			je 		@nxvdb
		loop 	@lp
		test 	ecx,ecx
		jz	 	@okay
@nxvdb:

		; ------- check for external vdb ------- ;
		.if		ExternalVdb && ExternalVdbSize && !exvdb
			mov 	esi,ExternalVdb
			add 	esi,sizeof EXVDBINFO
			mov 	exvdb,1
			.while 	byte ptr [esi]
				mov 	lBuff[0],0
				invoke 	SendMessage,hCtl,LB_GETTEXT,lIndex,ADDR lBuff
				lea 	eax,[esi].szThreatName
				push 	eax
					
					strlen eax
					
					mov 	ecx,eax
				pop 	eax
				@lp2:
					inc 	eax
					dec 	ecx
					jecxz	@nosl
					cmp 	byte ptr [eax],'/'
				jne		@lp2
				jmp 	@nx
				@nosl:
					lea 	eax,[esi].szThreatName
					jmp 	@nx2
				@nx:
				inc 	eax
				@nx2:
				invoke 	lstrcmp,ADDR lBuff,eax
				.if 	zero?
					jmp 	@okay
				.endif
				add		esi,sizeof SVDBv2
			.endw
			SehPop
			return_0
		.endif
		
	@okay:
		
		invoke 	MyZeroMemory,ADDR lBuff,256
		lea 	eax,[esi].szThreatName
		invoke 	lstrcpy,ADDR lBuff,eax
		invoke 	SetDlgItemText,hAnvdb,IDC_TXT_THNAME,ADDR lBuff
		
		movzx 	eax,[esi].uVirusInfo.dwType
		test 	eax,VIRI_INFECTOR
		.if 	!zero?
			test 	eax,VIRI_EXE
			.if 	!zero?
				lea 	edx,szViriTypeVW
			.else
				lea 	edx,szViriTypeVirus
			.endif
		.else
			test 	eax,VIRI_TROJAN
			.if 	!zero?
				lea 	edx,szViriTypeTrojan
			.else
				cmp 	eax,0
				.if 	!zero?
					lea 	edx,szViriTypeWorm
				.else
					lea 	edx,szViriJunk
				.endif
			.endif
		.endif
		
		mov 	lType,edx
		
		invoke 	SetDlgItemText,hAnvdb,IDC_TXT_THTYPE,lType
		
		movzx	eax,[esi].uVirusInfo.dwType
		test 	eax,VIRI_EXE
		.if 	!zero?
			lea 	edx,szViriExe
		.else
			test 	eax,VIRI_DLL
			.if 	!zero?
				lea 	edx,szViriDLL
			.else
				test 	eax,VIRI_COM
				.if 	!zero?
					lea 	edx,szViriCom
				.else
					test 	eax,VIRI_MACRO
					.if 	!zero?
						lea 	edx,szViriMacro
					.else
						test 	eax,VIRI_VBS
						.if 	!zero?
							lea 	edx,szViriVbs
						.else
							lea 	edx,szViriJunk
						.endif
					.endif
				.endif
			.endif
		.endif
		
		invoke 	SetDlgItemText,hAnvdb,IDC_TXT_FILETYPE,edx
		
		movzx 	eax,[esi].uVirusInfo.Risk
		.if 	eax == VIRI_RISK_VERYLOW
			lea 	edx,szRiskVeryLow
		.elseif 	eax == VIRI_RISK_LOW
			lea 	edx,szRiskLow
		.elseif 	eax == VIRI_RISK_MEDIUM
			lea 	edx,szRiskMedium
		.elseif 	eax == VIRI_RISK_HIGH
			lea 	edx,szRiskHigh
		.elseif 	eax == VIRI_RISK_VERYHIGH
			lea 	edx,szRiskVeryHigh
		.elseif 	eax == VIRI_RISK_DANGEROUS
			lea 	edx,szRiskDanger
		.else
			lea 	edx,szUnknown
		.endif
		
		invoke 	SetDlgItemText,hAnvdb,IDC_TXT_RISK,edx
		
		mov 	eax,[esi].uVirusInfo.Description
		.if 	!eax
			lea 	eax,szKosong
		.endif
		invoke 	SetDlgItemText,hAnvdb,1013,eax
		
		assume 	esi:nothing
		
		pop 	esi
		
		; ------- seh trapper ------- ;
		SehTrap 	__avlp
			ErrorDump 	"AnvdbListProc",offset AnvdbListProc,"AnvdbDlg.asm"
		SehEnd		__avlp
	.endif
	
	invoke 	CallWindowProc,lpListWndProc,hCtl,uMsg,wParam,lParam
	ret

AnvdbListProc endp

align 16

BuildAnvdbDlg proc uses ebx edi esi hWin:DWORD
	LOCAL 	lBuff[256+1]:BYTE
	
	
	invoke 	MyZeroMemory,ADDR lBuff,256
	invoke 	SendMessage,hWin,WM_SETICON,ICON_SMALL,hMainIcon
	
	invoke 	GetSysColor,COLOR_3DDKSHADOW
	invoke 	TxtColor,hWin,hInstance,reparg("Ansav Threats Database"),200,5,170,15,eax,0
	invoke 	ShowWindow,eax,SW_SHOW
	
	invoke 	wsprintf,ADDR lBuff,ADDR szVdbVerF,dwRDDay,dwRDMonth,dwRDYear
	
	invoke 	TxtColor,hWin,hInstance,ADDR lBuff,220,25,150,15,00FF0550h,-1
	invoke 	ShowWindow,eax,SW_SHOW
	
	; ------- set first ------- ;
	mov 	ebx,SetDlgItemText
	lea 	esi,szStrip
	
	push 	edi
	mov 	edi,hAnvdb
	
	scall 	ebx,edi,IDC_TXT_AUTHOR,esi 
	scall 	ebx,edi,IDC_TXT_FILETYPE,esi
	scall 	ebx,edi,IDC_TXT_ORIGIN,esi
	scall 	ebx,edi,IDC_TXT_RISK,esi
	scall 	ebx,edi,IDC_TXT_THNAME,esi
	scall 	ebx,edi,IDC_TXT_THTYPE,esi
	
	pop 	edi
	
	ret

BuildAnvdbDlg endp

align 16

PopulateVdbListThread proc uses edi esi ebx lParam:DWORD
	LOCAL 	Count:DWORD
	LOCAL 	lBuff[512+1]:BYTE
	LOCAL 	exvdb:DWORD
	
	mov 	edi,EnableWindow
	
	scall 	edi,hAnvdbList,FALSE
	scall 	edi,hAnvdbCmdClose,FALSE
	scall 	edi,hAnvdbCmdReload,FALSE
	
	mov 	exvdb,0
	
	call 	GetAllVdbCount
	.if 	eax
		mov 	Count,eax
		
		mov 	ebx,SendMessage
		
		scall 	ebx,hAnvdbPB,PBM_SETRANGE32,0,eax
		invoke 	MyZeroMemory,ADDR lBuff,512
		invoke 	wsprintf,ADDR lBuff,ADDR szdTosF,Count
		invoke 	SetDlgItemText,hAnvdb,IDC_TXT_THREATCNT,ADDR lBuff
		
		lea 	esi,AnsavVDBv2
		assume 	esi:ptr SVDBv2
		mov 	Count,0
		scall 	ebx,hAnvdbList,LB_RESETCONTENT,0,0
		@lp:
			
			cmp 	StopBuildVdb,1
			je 		@end
			
			lea 	edi,[esi].szThreatName
			invoke 	IsSuspName,edi
			.if 	!eax
				
				strlen edi
				
				cld
				mov 	ecx,eax
				mov 	al,'/'
				repnz 	scasb
				.if 	!ecx
					lea 	edi,[esi].szThreatName
				.endif
				scall 	ebx,hAnvdbList,LB_ADDSTRING,0,edi
			.endif
			add 	esi,sizeof SVDBv2
			inc 	Count
			scall 	ebx,hAnvdbPB,PBM_SETPOS,Count,0
			
		cmp 	byte ptr [esi],0
		jne 	@lp
		
		; ------- check vor exvdb ------- ;
		.if 	ExternalVdb && ExternalVdbSize && !exvdb
			mov 	esi,ExternalVdb
			add 	esi,sizeof EXVDBINFO
			mov 	exvdb,1
			jmp 	@lp
		.endif
		
		
		assume 	esi:nothing
		
	.else
		ViewError 	hAnvdb,"ERROR: Cannot populate VDB, maybe ANSAV installation corrupted, please reinstall ANSAV."
	.endif
	
@end:
	mov 	esi,EnableWindow
	xor 	edi,edi
	inc 	edi
	scall 	esi,hAnvdbCmdClose,edi
	scall 	esi,hAnvdbCmdReload,edi
	scall 	esi,hAnvdbList,edi
	invoke 	EndDialog,hAnvdbBuilder,0
	invoke 	ExitThread,0
	

	ret

PopulateVdbListThread endp

Align 8

PopulateVdbListProc proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD 
	LOCAL 	thID:DWORD
	
	mov 	eax,uMsg
	.if 	eax == WM_INITDIALOG
		
		m2m 	hAnvdbBuilder,hWin		
		
		invoke 	GetDlgItem,hWin,1001
		mov 	hAnvdbPB,eax
		
		mov 	StopBuildVdb,0
		
		mov 	eax,lParam
		.if 	eax==ANVDB_POPULATE_LIST
			invoke 	SetDlgItemText,hWin,1002,reparg("Populate Threat List from Database")
			invoke 	CreateThread,0,0,ADDR PopulateVdbListThread,0,0,ADDR thID
			invoke 	CloseHandle,eax
		.elseif 	eax == ANVDB_SAVE_LIST
			
			invoke 	SetDlgItemText,hWin,1002,reparg("Saving Threats Name to a File")
			lea 	edx,SaveVDBToTxt
			invoke 	CreateThread,0,0,edx,0,0,ADDR thID
			invoke 	CloseHandle,eax
			
		.endif
		
	.elseif 	eax == WM_COMMAND
		mov 	eax,wParam
		.if 	eax == IDC_ANVDBBP_CANCEL
			mov 	StopBuildVdb,1
		.endif
	.elseif 	eax == WM_CLOSE
		invoke 	EndDialog,hWin,0
	.endif
	
	xor 	eax,eax
	ret

PopulateVdbListProc endp

align 16

PopulateVdbList proc
	
	invoke 	ShowWindow,hAnvdb,SW_SHOW
	invoke 	DialogBoxParam,hInstance,IDD_ANVDBBP,hAnvdb,ADDR PopulateVdbListProc,ANVDB_POPULATE_LIST
	
	ret

PopulateVdbList endp

align 16

GetanVdbItemCtl proc uses esi
	
	mov 	esi,GetDlgItem
	
	scall 	esi,hAnvdb,1001 ; ------- list ------- ;
	mov 	hAnvdbList,eax
	lea 	eax,AnvdbListProc
	invoke 	SetWindowLong,hAnvdbList,GWL_WNDPROC,eax
	mov 	lpListWndProc,eax
	
	scall 	esi,hAnvdb,IDC_ANVDB_RELOAD
	mov 	hAnvdbCmdReload,eax
	scall 	esi,hAnvdb,IDC_ANVDB_CLOSE
	mov 	hAnvdbCmdClose,eax
	
	ret

GetanVdbItemCtl endp

align 16

SaveVDBToTxt proc uses esi edi ebx lParam:DWORD
	
	LOCAL 	ofn:OPENFILENAME
	LOCAL 	filen[MAX_PATH+1]:BYTE
	LOCAL 	threat[30]:BYTE
	LOCAL 	buff[256]:BYTE
	LOCAL 	hlist2,tmp:DWORD
	
	lea 	esi,ofn
	lea 	edi,filen
	
	mov 	ebx,MyZeroMemory
	
	scall 	ebx,esi,sizeof OPENFILENAME
	scall 	ebx,edi,MAX_PATH
	lea 	eax,threat
	scall 	ebx,eax,30
	lea 	eax,buff
	scall 	ebx,eax,256
	
	invoke 	ShowWindow, hAnvdbBuilder,SW_HIDE
	
	mov 	[ofn.lStructSize],sizeof OPENFILENAME
	mov2 	[ofn.hwndOwner],hAnvdb
	mov2 	[ofn.hInstance],hInstance
	mov 	[ofn.lpstrFilter],offset szMaskTxt
	mov 	[ofn.nMaxFile],256
	mov 	[ofn.lpstrFile],edi
	invoke 	GetSaveFileName,esi
	.if		!byte ptr [edi]
		invoke 	EndDialog,hAnvdbBuilder,0
		return_0
	.endif
	
	invoke 	lstrlen,edi
	add 	eax,edi
	dec 	eax
	.while  byte ptr [eax]!='.' && byte ptr [eax]!=0
		dec eax
		.if 	byte ptr [eax]=='\'
			invoke 	lstrcat,edi,reparg(".txt")
			.break
		.endif
	.endw
	
	invoke 	CreateFile,edi,
			GENERIC_WRITE,
			FILE_SHARE_WRITE,0,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,0
	.if 	eax!=-1
		mov 	esi,eax
		
		invoke 	ShowWindow, hAnvdbBuilder,SW_SHOW
		
		; ------- shorted ------- ;
		; ASCENDING
		
		invoke 	SendMessage,hAnvdbList,LB_GETCOUNT,0,0
		mov 	tmp,eax
		
		analloc 1024*2
		.if 	eax
			mov 	ebx,eax
			invoke 	wsprintf,ebx,offset szThreatTxtF, \
					VerMajor,VerMinor,VerRevision, \
					dwRDDay,dwRDMonth,dwRDYear,tmp 
			invoke 	lstrlen,ebx
			invoke 	WriteFile,esi,ebx,eax,offset brw,0
			anfree 	ebx
		.endif
		
		mov 	ebx,tmp
		push 	ebx
		
		invoke 	SendMessage,hAnvdbPB, PBM_SETRANGE32,0,ebx
		
		invoke 	GetDlgItem,hAnvdb,1024
		mov 	hlist2,eax
		mov 	tmp,0
		invoke 	SendMessage,eax,LB_RESETCONTENT,0,0
		.while 	ebx
			dec 	ebx
			invoke 	SendMessage,hAnvdbList,LB_GETTEXT,ebx,ADDR threat
			invoke 	SendMessage,hlist2,LB_ADDSTRING,0,ADDR threat
			invoke 	SendMessage,hAnvdbPB, PBM_SETPOS,tmp,0
			add tmp,1
		.endw
		
		pop 	ebx
		
		push 	edi
		
		xor 	edi,edi
		.while 	ebx
			dec 	ebx
			mov 	threat[0],0
			invoke 	SendMessage,hlist2,LB_GETTEXT,edi,ADDR threat
			inc 	edi
			invoke 	wsprintf,ADDR buff,reparg("%d. %s"),edi,ADDR threat
			invoke 	lstrlen,ADDR buff
			lea 	ecx,buff
			mov 	word ptr [ecx+eax],0a0dh
			add 	eax,2 
			invoke	WriteFile,esi,ecx,eax,offset brw,0
		.endw
		
		pop 	edi
		
		invoke 	CloseHandle,esi
		
		invoke 	MessageBox,hAnvdb, \
				reparg("Threat list name generated. Open in notepad now?"), \
				offset szAppName,MB_YESNO or MB_ICONQUESTION
		.if 	eax==IDYES
			invoke 	ShellExecute,hAnvdb,offset szOpen,edi,0,0,SW_SHOWMAXIMIZED
		.endif
		
	.else
		ViewError	hAnvdb,"Cannot create file."
	.endif
	
	invoke 	EndDialog,hAnvdbBuilder,0
	invoke 	ExitThread,0
	
	ret

SaveVDBToTxt endp

align 16


AnvdbDlgProc proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	LOCAL hDC   :DWORD
	LOCAL hOld  :DWORD
	LOCAL memDC :DWORD
	LOCAL ps,tmp:DWORD
	
	mov 	eax,uMsg
	.if 	eax == WM_INITDIALOG
		
		mov2 	hAnvdb,hWin
		
		.if 	TimeForBlind
			call 	ChangeRandomString
			invoke 	SetWindowText,hWin,ADDR szRandomString 
		.endif
		
		invoke 	BuildAnvdbDlg,hWin
		
		; ------- Get item ------- ;
		call 	GetanVdbItemCtl
		; ------- Populate vdb ------- ;
		call 	PopulateVdbList
		
		invoke 	SetFocus,hWin
	.elseif 	eax == WM_COMMAND
		mov 	eax,wParam
		.if 	eax == IDC_ANVDB_CLOSE
			jmp 	@close
		.elseif 	eax == IDC_ANVDB_RELOAD
			call 	PopulateVdbList
		.elseif 	eax == 1023	; <-- SAVE ;
			invoke 	DialogBoxParam,hInstance,IDD_ANVDBBP,hWin,ADDR PopulateVdbListProc,ANVDB_SAVE_LIST
		.endif
		
	.elseif 	eax == WM_PAINT
		
		invoke LocalAlloc,LPTR,sizeof PAINTSTRUCT
		mov 	ps,eax
		
		invoke  BeginPaint,hWin,ps
		mov     hDC, eax
		
		invoke  CreateCompatibleDC,hDC
		mov     memDC, eax
		
		invoke 	LoadBitmap,hInstance,IMG_BOOK
		mov 	tmp,eax
		invoke 	SetBmpColor,eax
		invoke  SelectObject,memDC,eax
		mov     hOld, eax
		
		invoke  BitBlt,hDC,5,3,300,50,memDC,0,0,SRCCOPY
		invoke  SelectObject,hDC,hOld
		invoke  DeleteDC,memDC
		
		invoke  EndPaint,hWin,ps
		invoke  ReleaseDC,hWin,hDC
		
		invoke 	LocalFree,ps
		invoke 	DeleteObject,tmp
		
	.elseif 	eax == WM_CLOSE
	@close:
		invoke 	EndDialog,hWin,0
	.endif
	
	
	xor 	eax,eax
	ret

AnvdbDlgProc endp



