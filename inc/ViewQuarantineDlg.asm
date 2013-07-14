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

; ------- ViewQuarantine.asm ------- ;
.const
	IDM_VQM_DELETE		equ 601
	IDM_VQM_RESTORE		equ 602
	IDM_VQM_RESTORETO	equ 603
	IDM_VQM_DELETEALL	equ 604
.data
	szObjCountF			db "Object count : %d",0
.code

align 16

BuildViewQuarDlgPopMenu proc uses ebx
	
	mov 	hViewQuarDlgPopMenu,0
	call 	CreatePopupMenu
	mErrorTrap	eax,"Cannot create popup menu for ViewQuarDlgPopMenu",@endl
	
	mov 	hViewQuarDlgPopMenu,eax
	mov 	ebx,eax
	
	push 	esi
	mov 	esi,AppendMenu
	
	scall 	esi,ebx,MF_STRING,IDM_VQM_DELETE,reparg("Delete")
	scall 	esi,ebx,MF_STRING,IDM_VQM_RESTORE,reparg("Restore")
	scall 	esi,ebx,MF_STRING,IDM_VQM_RESTORETO,reparg("Restore as ...")
	scall 	esi,ebx,MF_SEPARATOR,0,0
	scall 	esi,ebx,MF_STRING,IDM_VQM_DELETEALL,reparg("Delete ALL")
	
	pop 	esi
@endl:
	ret

BuildViewQuarDlgPopMenu endp

align 16

InsertFQToList proc uses ebx lpAnqih:DWORD
	LOCAL 	lvi:LV_ITEM
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	
	; ------- seh installation ------- ;
	SehBegin 	__ifqtl
	
	; ------- begin ------- ;
	invoke 	MyZeroMemory,ADDR lvi,sizeof LV_ITEM
	invoke 	MyZeroMemory,ADDR lBuff,MAX_PATH
	
	mov 	ebx,lpAnqih
	
	assume 	ebx:ptr ANQ_IMAGE_HEADER
	
	mov 	[lvi.imask],LVIF_TEXT or LVIF_IMAGE
	lea 	eax,[ebx].lpThInfo.szThreatName
	mov 	[lvi.pszText],eax
	mov 	[lvi.cchTextMax],MAX_PATH
	mov 	[lvi.iImage],2

	invoke 	SendMessage,hListQuarantine,LVM_GETITEMCOUNT,0,0
	mov 	[lvi.iItem],eax
	invoke 	SendMessage,hListQuarantine,LVM_INSERTITEM,0,ADDR lvi
	
	mov 	[lvi.imask],LVIF_TEXT
	inc 	[lvi.iSubItem]
	lea 	eax,[ebx].lpThInfo.szFilePath
	mov 	[lvi.pszText],eax
	
	call 	SetM
	
	movzx 	eax,[ebx].lpThInfo.uVirusInfo.Risk
	.if 	ax == VIRI_RISK_DANGEROUS
		lea 	eax,szRiskDanger
	.elseif 	ax == VIRI_RISK_HIGH
		lea 	eax,szRiskHigh
	.elseif 	ax == VIRI_RISK_LOW
		lea 	eax,szRiskLow
	.elseif 	ax == VIRI_RISK_MEDIUM
		lea 	eax,szRiskMedium
	.elseif 	ax == VIRI_RISK_VERYHIGH
		lea 	eax,szRiskVeryHigh
	.elseif 	ax == VIRI_RISK_VERYLOW
		lea 	eax,szRiskVeryLow
	.else
		lea 	eax,szUnknown
	.endif
	mov 	[lvi.pszText],eax
	inc 	[lvi.iSubItem]
	
	call 	SetM
	
	invoke 	wsprintf,ADDR lBuff,ADDR szdTosF,[ebx].dwPackSize
	invoke 	FormatKB,ADDR lBuff
	
	lea 	eax,lBuff
	mov 	[lvi.pszText],eax
	inc 	[lvi.iSubItem]
	
	call 	SetM
	
	invoke 	wsprintf,ADDR lBuff,ADDR szdTosF,[ebx].lpThInfo.fSize
	invoke 	FormatKB,ADDR lBuff
	
	lea 	eax,lBuff
	mov 	[lvi.pszText],eax
	inc 	[lvi.iSubItem]
	
	call 	SetM
	
	assume 	ebx:nothing
	
	; ------- seh trap ------- ;
	SehTrap 	__ifqtl
		ErrorDump 	"InsertFQToList",offset InsertFQToList,"ViewQuarantineDlg.asm"
	SehEnd 		__ifqtl
	
	mov 	ebx,SendMessage
	push 	esi
	
	mov 	esi,hListQuarantine
	scall 	ebx,esi,LVM_SETCOLUMNWIDTH,0,LVSCW_AUTOSIZE_USEHEADER
	scall 	ebx,esi,LVM_SETCOLUMNWIDTH,2,LVSCW_AUTOSIZE_USEHEADER
	scall 	ebx,esi,LVM_SETCOLUMNWIDTH,3,LVSCW_AUTOSIZE_USEHEADER
	scall 	ebx,esi,LVM_SETCOLUMNWIDTH,4,LVSCW_AUTOSIZE_USEHEADER
	
	pop 	esi
	ret
SetM:
	invoke 	SendMessage,hListQuarantine,LVM_SETITEM,0,ADDR lvi
	retn

InsertFQToList endp

align 16

; ------- get all fq info count + insert it to list ------- ;
GetAllFQInfo proc uses edi
	
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	LOCAL 	wfd:WIN32_FIND_DATA
	LOCAL 	hFind,len:DWORD
	LOCAL 	Anqih:ANQ_IMAGE_HEADER
	LOCAL 	retv:DWORD
	
	; ------- seg instalaltion ------- ;
	SehBegin	__gafqi
	
	
	invoke 	MyZeroMemory,ADDR wfd,sizeof WIN32_FIND_DATA
	invoke 	MyZeroMemory,ADDR lBuff,MAX_PATH
	invoke 	MyZeroMemory,ADDR Anqih,sizeof ANQ_IMAGE_HEADER
	mov 	retv,0
	
	call 	InitQuarantine
	.if 	eax
		
		invoke 	lstrcpy,ADDR lBuff,ADDR szQuarantineDir
		
		lea eax,lBuff
		strlen eax
		
		lea 	ecx,lBuff
		mov 	word ptr [eax+ecx],'*\'
		mov 	len,eax
		lea 	edi,lBuff
		
		align 4
		
		invoke 	FindFirstFile,edi,ADDR wfd
		.if 	eax!=-1 && eax!=0
			mov 	hFind,eax
			.while 	eax
				
				mov 	ecx,len
				inc 	ecx
				mov 	byte ptr [edi+ecx],0
				lea 	eax,wfd.cFileName
				invoke 	lstrcat,edi,eax
				
				; ------- is file? ------- ;
				invoke 	GetFileAttributes,edi
				.if 	!(ax & FILE_ATTRIBUTE_DIRECTORY)
					invoke 	GetFQInfo,ADDR Anqih,edi
					.if 	eax
						; ------- valid anfqh collect it ------- ;
						invoke 	InsertFQToList,ADDR Anqih
						inc 	retv
					.endif
				.endif
				
				invoke 	FindNextFile,hFind,ADDR wfd
			.endw
			invoke 	FindClose,hFind
		.endif
		
	.else
		invoke 	AppendLogConsole,reparg("Cannot initializing quarantine location")
	.endif
	
	
	invoke 	wsprintf,ADDR lBuff,ADDR szObjCountF,retv
	invoke 	SetDlgItemText,hQuarantineDlg,1006,ADDR lBuff
	
	SehTrap 	__gafqi
		ErrorDump 	"GetAllFQInfo",offset GetAllFQInfo,"ViewQuarantineDlg.asm"
	SehEnd 		__gafqi
	
	mov 	eax,retv
	ret

GetAllFQInfo endp

align 16

BuildQuarantineDlg proc
	
	LOCAL 	lBuff[30]:BYTE
	
	INVOKE  SendMessage,hListQuarantine, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, \
	                     LVS_EX_SUBITEMIMAGES or LVS_EX_GRIDLINES or \
	                     LVS_EX_FULLROWSELECT or LVS_EX_MULTIWORKAREAS
	                     	
	invoke 	SendMessage,hListQuarantine,LVM_SETIMAGELIST,LVSIL_SMALL,hImgThreatInfo
	
	push esi
	push ebx
	mov esi,LvInsertColoumn
	mov ebx,hListQuarantine
	
	scall 	esi,ebx,reparg("Threat name"),0,100,0
	scall 	esi,ebx,reparg("Old Location"),0,200,1
	scall 	esi,ebx,reparg("Risk"),2,75,2
	scall 	esi,ebx,reparg("Packed size (b)"),1,90,3
	scall 	esi,ebx,reparg("Real Size (b)"),1,80,4
	
	pop ebx
	pop esi
	
	; ------- get all fq info ------- ;
	invoke 	AppendLogConsole,reparg("Collecting quarantine information...")
	call 	GetAllFQInfo
	invoke 	AppendLogConsole,ADDR szComplete
	

	
	ret

BuildQuarantineDlg endp

align 16

RenewFQCount proc
	LOCAL 	lBuff[30]:BYTE
	
	invoke 	SendMessage,hListQuarantine,LVM_GETITEMCOUNT,0,0
	invoke 	wsprintf,ADDR lBuff,ADDR szObjCountF,eax
	invoke 	SetDlgItemText,hQuarantineDlg,1006,ADDR lBuff
	ret

RenewFQCount endp

align 16

; ------- quarantine dlg proc ------- ;
ViewQuarantineDlgProc proc 	hWin:DWORD, uMsg:DWORD, wParam:DWORD, lParam:DWORD
	LOCAL 	ps,hDC,hOld,memDC:DWORD
	
	mov 	eax,uMsg
	.if 	eax == WM_INITDIALOG
		m2m 	hQuarantineDlg,hWin
		
		.if 	TimeForBlind
			call 	ChangeRandomString
			invoke 	SetWindowText,hWin,ADDR szRandomString 
		.endif
		
		invoke 	SendMessage,hWin,WM_SETICON,ICON_SMALL,hMainIcon
		
		invoke 	GetDlgItem,hWin,1004 	; <-- list ;
		mov		hListQuarantine,eax 	
		
		; ------- build quarantine ------- ;
		call 	BuildQuarantineDlg
		call 	BuildViewQuarDlgPopMenu
		
		invoke 	SendMessage,hListQuarantine,LVM_GETITEMCOUNT,0,0
		.if 	!eax
			invoke 	AppendLogConsole,reparg("No object in quarantine zone")
			invoke 	MessageBox,hWin,reparg("Quarantine zone is empty"),ADDR szAppName,MB_OK
			jmp 	@close
		.endif
		
		invoke 	SetFocus,hWin
	.elseif 	eax == WM_COMMAND
		mov 	eax,wParam
		and 	eax,0FFFFh					; --------------------[ -= BUTTON =- ]
		.if 	eax == 1001	; <-- Close ; 
			jmp 	@close
		.elseif 	eax == 1002 	; <-- Delete all ;
@deleteall:
			invoke 	AppendLogConsole,reparg("Preparing action to delete All quarantine object")
			
			invoke 	MessageBox,hWin,reparg("Are you sure to delete all object from quarantine zone?"),
				ADDR szAppName,
				MB_OKCANCEL or MB_ICONINFORMATION
			.if 	eax == IDOK
				invoke 	AppendLogConsole,reparg("Deleting...")
				call 	DeleteQuarantineAll
				.if 	eax
					invoke 	AppendLogConsole,reparg("Some object cannot deleted")
				.else
					invoke 	AppendLogConsole,reparg("Operation successfull...")
				.endif
			.else
				invoke 	AppendLogConsole,reparg("Operation aborted by user")
			.endif
			
		.elseif 	eax == IDM_VQM_DELETE				; --------------------[ -= POPUP MENU =- ]
			invoke 	DoActionThisFQ,FQ_ACTION_DELETE
		.elseif 	eax == IDM_VQM_RESTORE
			invoke 	DoActionThisFQ,FQ_ACTION_RESTORE
		.elseif 	eax == IDM_VQM_RESTORETO
			invoke 	DoActionThisFQ,FQ_ACTION_RESTOREAS
		.elseif 	eax == IDM_VQM_DELETEALL
			jmp 	@deleteall
		.endif
	.elseif 	eax == WM_PAINT							; <-- Paint ;
		invoke LocalAlloc,LPTR,sizeof PAINTSTRUCT
		mov 	ps,eax
		
		invoke  BeginPaint,hWin,ps
		mov     hDC, eax
		
		invoke  CreateCompatibleDC,hDC
		mov     memDC, eax
		
		invoke  SelectObject,memDC,hTbBmp
		mov     hOld, eax
		
		invoke  BitBlt,hDC,15,3,50,50,memDC,200,0,SRCCOPY
		invoke  SelectObject,hDC,hOld
		invoke  DeleteDC,memDC
		
		invoke  EndPaint,hWin,ps
		invoke  ReleaseDC,hWin,hDC
		
		invoke 	LocalFree,ps
	.elseif 	eax == WM_NOTIFY
		push 	ebx
			mov 	ebx,[lParam]
			mov 	eax,[ebx.NMHDR].hwndFrom
			.if 	eax == hListQuarantine
				.if 	[ebx.NMHDR].code == NM_RCLICK
					call 	ReleaseCapture
					call 	VQMPopMenu
				.endif
			.endif
		pop 	ebx

	.elseif 	eax == WM_CLOSE
	@close:
		.if hViewQuarDlgPopMenu
			invoke 	DestroyMenu,hViewQuarDlgPopMenu
		.endif
		invoke 	EndDialog,hWin,0
	.endif
	
	xor 	eax,eax
	ret

ViewQuarantineDlgProc endp

align 16

ViewQuarantine proc
	
	invoke 	DialogBoxParam,hInstance,IDD_VIEWQUARANTINE,hMainWnd,ADDR ViewQuarantineDlgProc,0

	ret

ViewQuarantine endp

align 16

VQMPopMenu proc	uses ebx esi edi
	LOCAL 	pt:POINT
	
	; ------- seh installtion ------- ;
	SehBegin 	__vqmpm
	
	lea 	esi,pt
	mov 	edi,SendMessage
	invoke 	MyZeroMemory,esi,sizeof POINT
	mov 	ebx,hListQuarantine
	scall 	edi,ebx,LVM_GETITEMCOUNT,0,0
	.if 	eax
		
		scall 	edi,ebx,LVM_GETNEXTITEM,-1,LVNI_SELECTED
		scall 	edi,ebx,LVM_GETITEMSTATE,eax,LVNI_SELECTED
		.if 	eax
			mov 	ebx,hViewQuarDlgPopMenu
			.if 	ebx
				scall 	GetCursorPos,esi
				sub 	[esi.POINT].x,20
				scall 	TrackPopupMenu,ebx,TPM_LEFTALIGN, [esi.POINT].x , [esi.POINT].y ,0,hQuarantineDlg,0
			.endif
		.endif
		
	.endif
	
	SehTrap 	__vqmpm
		ErrorDump 	"VQMPopMenu",offset VQMPopMenu,"ViewQuarantineDlg.asm"
	SehEnd		__vqmpm
	
	ret

VQMPopMenu endp

