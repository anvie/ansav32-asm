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

;### SEE - TODO3: ###


; ------- Maindlgctrl.asm ------- ;
; for all stuff about main window
.data?
	hToolsPopMenu		dd ?			
.data
	IDM_MPM_PROPERTIES	equ 600
	IDM_MPM_GOTOOBJL	equ 601
	IDM_MPM_SELECTALL	equ	602
	IDM_MPM_CLEAN		equ 603
	IDM_MPM_DELETE		equ 604
	IDM_MPM_QUARANTINE	equ 605
	IDM_MPM_SIGNASTRUST equ 606
	IDM_MPM_COPYTHREATN	equ 607
	IDM_MPM_COPYOBJPATH equ 608
.code

align 16

; ------- build popup menu in main list view ------- ;
BuildMainPopMenu	proc uses ebx esi edi
	
	mov 	hMainPopMenu,0
	call 	CreatePopupMenu
	mErrorTrap	eax,"Cannot create main popup menu, in BuildMainPopMenu",@endl
	
	mov 	hMainPopMenu,eax
	mov 	ebx,eax
	mov 	esi,AppendMenu
	
	
	mov 	edi,MF_STRING

	scall	esi,ebx,edi,IDM_MPM_GOTOOBJL,reparg("Goto object location")
	scall	esi,ebx,MF_SEPARATOR,0,0
	scall	esi,ebx,edi,IDM_MPM_SELECTALL,reparg("Select ALL")
	scall	esi,ebx,MF_SEPARATOR,0,0
	scall	esi,ebx,edi,IDM_MPM_CLEAN,reparg("Clean selected object")
	scall	esi,ebx,edi,IDM_MPM_DELETE,reparg("Delete selected object ")
	scall	esi,ebx,edi,IDM_MPM_QUARANTINE,reparg("Quarantine selected object")
	scall	esi,ebx,MF_SEPARATOR,0,0
	scall	esi,ebx,edi,IDM_MPM_SIGNASTRUST,reparg("Sign this file as trusted")
	scall	esi,ebx,MF_SEPARATOR,0,0
	scall	esi,ebx,edi,IDM_MPM_COPYTHREATN,reparg("Copy this threat name")
	scall	esi,ebx,edi,IDM_MPM_COPYOBJPATH,reparg("Copy this object path")
	
	; ------- icon ------- ;

@endl:
	ret

BuildMainPopMenu endp

align 16

BuildPlugins proc
	
	LOCAL 	mi:MENUITEMINFO
	
	invoke 	MyZeroMemory,ADDR mi,sizeof MENUITEMINFO
	
; ------- STANDARD TOOLS ------- ;
	mov 	[mi.cbSize],sizeof MENUITEMINFO
	mov 	[mi.fMask],MIIM_DATA or MIIM_ID or MIIM_STATE or MIIM_SUBMENU or MIIM_TYPE or MIIM_CHECKMARKS
	
	call 	InitPlugins

	ret

BuildPlugins endp

align 16

GetObjectPath proc lpBuffer:DWORD,iItem:DWORD
	
	LOCAL 	lvi:LV_ITEM
	
	invoke 	MyZeroMemory,ADDR lvi,sizeof LV_ITEM
	
	mov 	[lvi.imask],LVIF_TEXT
	m2m 	[lvi.iItem],iItem
	inc 	[lvi.iSubItem]
	m2m 	[lvi.pszText],lpBuffer
	mov 	[lvi.cchTextMax],MAX_PATH
	invoke 	SendMessage,hMainList,LVM_GETITEM,0,ADDR lvi
	
	ret

GetObjectPath endp

align 16

SetMainTxtStatus2 proc uses edi lpStatus1:DWORD,lpStatus2:DWORD
	LOCAL 	lBuff[256+1]:BYTE
	
	lea 	edi,lBuff
	invoke 	MyZeroMemory,edi,256
	
	invoke 	lstrcpy,edi,lpStatus1
	.if 	lpStatus2
		
		strlen edi
		
		mov 	dword ptr [edi+eax],00202D20h
		invoke 	lstrcat,edi,lpStatus2
	.endif
	
	invoke 	SetWindowText,hMainTxtStatus,edi
	
	ret

SetMainTxtStatus2 endp

align 16

SetMainTxtStatus proc uses esi lpStatus:DWORD
	
	mov 	esi,ShowWindow
	
	.if 	lpStatus == STATUS_DETECTED
		scall 	esi,hTxtStatusClean,SW_HIDE
		scall 	esi,hTxtStatusDetc,SW_SHOW
	.elseif 	lpStatus == STATUS_CLEAN
		scall 	esi,hTxtStatusDetc,SW_HIDE
		scall 	esi,hTxtStatusClean,SW_SHOW
		.if 	MemCheck
			invoke 	SetWindowText,hTxtStatusClean,reparg("Memory is Clean...")
		.else
			invoke 	SetWindowText,hTxtStatusClean,reparg("Threat not detected")
		.endif
	.else
		scall 	esi,hTxtStatusDetc,SW_HIDE
		scall 	esi,hTxtStatusClean,SW_HIDE
	.endif
	
	ret

SetMainTxtStatus endp

align 16

LvInsertColoumn proc hWnd:DWORD,lpTitle:DWORD,lvcAlign:DWORD,wt:DWORD,stg:DWORD
	
	LOCAL 	lvc:LV_COLUMN
	
	
	invoke 	MyZeroMemory,ADDR lvc,sizeof LV_COLUMN
	
	mov 	lvc.imask,LVCF_TEXT OR LVCF_WIDTH
	.if 	lvcAlign
		or 		lvc.imask,LVCF_FMT
		mov 	eax,lvcAlign
		mov 	[lvc.fmt],eax
	.endif
	m2m 	lvc.pszText,lpTitle
	mov 	lvc.cchTextMax,256
	m2m 	lvc.lx,wt
	invoke 	SendMessage,hWnd,LVM_INSERTCOLUMN,stg,ADDR lvc
	
	ret

LvInsertColoumn endp

align 16

; ------- Stuff for build all of needed for Listview in main wnd ------- ;
BuildMainListview proc uses esi ebx

	mLog 	"BuildMainListview::"
	
	invoke 	GetDlgItem,hMainWnd,IDC_MAIN_LV
	mov 	hMainList,eax

	mov 	esi,SendMessage
	
    scall 	esi, hMainList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, \
                         LVS_EX_SUBITEMIMAGES or LVS_EX_GRIDLINES or \
                         LVS_EX_FULLROWSELECT
    scall 	esi,hMainList,LVM_SETTEXTCOLOR,0,00030FFh
    
    sub 	eax,eax
	mov 	hImgThreatInfo,eax
	mov		hBmpThreatInfo,eax
	invoke 	ImageList_Create,16,16,16,5,eax
IFDEF 	ERRORLOG
	.if 	!eax
		mErrorLog 	"-Cannot load hImgThreatInfo" 
	.endif
ENDIF
	mov 	hImgThreatInfo,eax
	invoke 	LoadBitmap,hInstance,BMPTHREATINFO
IFDEF 	ERRORLOG
	.if 	!eax
		mErrorLog 	"-Cannot load bitmap resource for res ID BMPTHREATINFO"
	.endif
ENDIF
	mov 	hBmpThreatInfo,eax
	
	.if 	hBmpThreatInfo && hImgThreatInfo
		invoke 	ImageList_Add,hImgThreatInfo,eax,0
		invoke 	SendMessage,hMainList,LVM_SETIMAGELIST,LVSIL_SMALL,hImgThreatInfo
	.endif
    
    mov 	esi,LvInsertColoumn
    mov 	ebx,hMainList
    
	scall 	esi,ebx,leatext("Threat Name"),0,100,0
	scall 	esi,ebx,leatext("Object Location"),0,127,1
	scall 	esi,ebx,leatext("Size (b)"),LVCFMT_RIGHT,70,2
	scall 	esi,ebx,leatext("Risk"),LVCFMT_CENTER,70,3
	scall 	esi,ebx,leatext("Info"),0,100,4
	
	invoke 	SetLastError,0
	
	ret

BuildMainListview endp

align 16

BuildMainTxtStatus proc

	invoke 	TxtColor,hMainWnd,hInstance,reparg("Threat Detected!"),300,288,150,15,0000FFh,10091
	mov 	hTxtStatusDetc,eax
	invoke 	ShowWindow,eax,SW_HIDE
	invoke 	TxtColor,hMainWnd,hInstance,reparg("Memory is Clean.."),300,288,150,15,0FF5500h,10091
	mov 	hTxtStatusClean,eax
	invoke 	ShowWindow,eax,SW_HIDE
	
	ret

BuildMainTxtStatus endp

align 16

SetMnuScanState proc uses esi
	
	LOCAL 	hMenu:DWORD
	
	invoke 	GetMenu,hMainWnd
	mov 	hMenu,eax
	call 	IsAnyRemovableExist
	
	mov 	esi,EnableMenuItem
	
	.if 	!eax
		scall 	esi,hMenu,IDM_FILE_SCANALLREM,MF_DISABLED or MF_GRAYED
	.else
		scall 	esi,hMenu,IDM_FILE_SCANALLREM,MF_ENABLED
	.endif
	
	
	ret

SetMnuScanState endp

align 16

SetActionTbState proc uses esi ebx edi lState:DWORD

	mov 	esi,SendMessage
	mov 	ebx,hToolBar
	mov 	edi,lState
	
	push 	ebp
	
	mov 	ebp,TB_ENABLEBUTTON
	
	scall 	esi,ebx,ebp,IDC_MAINTB_CLEAN,edi
	scall 	esi,ebx,ebp,IDC_MAINTB_DELETE,edi
	scall 	esi,ebx,ebp,IDC_MAINTB_QUARANTINE,edi
	
	pop 	ebp
	
	ret

SetActionTbState endp

align 16

SetAllMainCtrlState proc uses edi esi ebx
	
	mov 	esi,SetDlgItemText
	mov 	ebx,offset szNull
	mov 	edi,hMainWnd
	
	scall 	esi,edi,IDC_TXT_THREATDETC,ebx
	scall 	esi,edi,IDC_TXT_PERCENT,offset szNullPercent
	scall 	esi,edi,IDC_TXT_CHKFILES,ebx
	scall 	esi,edi,IDC_EDIT_PATH,offset szKosong
	invoke 	SendMessage,hMainProgBar,PBM_SETPOS,0,0

	ret

SetAllMainCtrlState endp

align 16

TimerForMonitorRemovable proc uses edi esi ebx ecx edx
	
	call 	SetMnuScanState
	ret

TimerForMonitorRemovable endp

align 16

SetMainTimer proc
	
	invoke 	SetTimer,hMainWnd,TMR_MONITOR_REMOVABLE,500,ADDR TimerForMonitorRemovable
	ret

SetMainTimer endp

align 16

KillMainTimer proc
	
	invoke 	KillTimer,hMainWnd,TMR_MONITOR_REMOVABLE 	; <-- suspend/kill monitoring removable ;
	ret

KillMainTimer endp

align 16

BuildToolbar proc uses esi

	LOCAL 	bSize:DWORD
	LOCAL 	tbab:TBADDBITMAP
	LOCAL 	tbb:TBBUTTON

	mov 	hTbBmp,0
	invoke 	LoadBitmap,hInstance,IMG_TBAR
	mov 	hTbBmp,eax
	
	invoke 	GetDlgItem,hMainWnd,IDC_MAIN_TB
	mov 	hToolBar,eax

	mov 	esi,SendMessage
	
	scall 	esi,hToolBar,TB_BUTTONSTRUCTSIZE,sizeof TBBUTTON,0
	
	mov 	ebx,49
	shl 	ebx,16
	mov 	bx,50
	scall 	esi,hToolBar,TB_SETBITMAPSIZE,0,ebx
	m2m 	tbab.hInst,0 ;HINST_COMMCTRL
	invoke 	SetBmpColor,hTbBmp
	mov 	hTbBmp,eax
	m2m 	tbab.nID,hTbBmp
	lea 	eax,tbab
	scall 	esi,hToolBar,TB_ADDBITMAP,7,eax
	lea 	eax,TbrArr
	scall 	esi,hToolBar,TB_ADDBUTTONS,TbrArrCnt,eax
	ret

BuildToolbar endp

align 16

SetMyControlColor 	proc hWnd:DWORD,hColor:DWORD
	
	invoke 	SetWindowLong,hWnd,4,hColor
	invoke 	SendMessage,hWnd,2194,0,0
	ret

SetMyControlColor endp

align 16

CheckAndProcessBVI proc uses esi
	
	LOCAL 	retv:DWORD
	
	mov 	retv,0
	.if 	BufferVirusInfoItemCount != 0
	
		; ------- Set item ------- ;
		invoke 	wsprintf,ADDR szDetectedThreatCntBuff,ADDR szdTosF,BufferVirusInfoItemCount
		invoke 	SetWindowText,hTxtDetectedThreats,ADDR szDetectedThreatCntBuff
		
		mov 	esi,pBufferVirusInfo
		mov 	ecx,BufferVirusInfoItemCount
		
		; ------- Memory check flag ------- ;
		
		@lp:
			push 	ecx
			
			invoke 	LvInsertTFIItem,esi
			add 	esi,sizeof THREATFULLINFO
			
			mov 	ecx,esi
			add 	ecx,BufferVirusInfoSize
			cmp 	esi,ecx
			ja 		@nomore
			
			pop 	ecx
		loop 	@lp
		@nomore:
		
		
		mov 	retv,1
	.endif
	
	invoke 	AppendLogConsole,offset szFlushBuffer
	; ------- Flush BVI ------- ;
	call 	CloseBufferVirusInfo
	
	; ------- Save result ------- ;
	lea 	esi,LastScannedInfo
	assume 	esi:ptr LASTSCANNEDINFO
	
	lea 	eax,[esi].szLocation
	invoke 	lstrcpyn,eax,ADDR szInMemory,MAX_PATH
	m2m 	[esi].dwFileScanned,AllFilesCount
	m2m 	[esi].dwThreatsDetected,BufferVirusInfoItemCount
	.if 	retv
		mov 	[esi].wStatus,STATUS_NOTTAKEACTION
	.endif
	mov 	[esi].lpFailedArray,0
	mov 	[esi].wFinished,1
	assume 	esi:nothing
	
	mov 	eax,retv
	ret

CheckAndProcessBVI endp

align 16

MainWndCleanUp proc uses esi
	.if 	hMainPopMenu
		invoke 	DestroyMenu,hMainPopMenu
	.endif
	.if 	hImgThreatInfo
		invoke 	ImageList_Destroy,hImgThreatInfo
	.endif
	mov 	esi,DeleteObject
	
	.if 	hBmpThreatInfo
		scall 	esi,hBmpThreatInfo
	.endif
	.if 	hTbBmp
		scall 	esi,hTbBmp
	.endif
	invoke 	KillTimer,hMainWnd,1234	; <-- kill timer for monitor removable media ;
	ret
MainWndCleanUp endp

align 16

RepositionMainWnd proc uses esi edi
	
	LOCAL 	hBtnScan,hBtnClean,hBtnDelete,hBtnQuarantine:DWORD
	LOCAL 	hBtnViewRes,hBtnExit:DWORD
	LOCAL 	left,top,wt:DWORD
	LOCAL 	rc:RECT
	LOCAL 	lvc:LV_COLUMN
	
	invoke 	MyZeroMemory,ADDR rc,sizeof RECT
	
	invoke 	GetClientRect,hMainWnd,ADDR rc
	
	mov 	eax,rc.right
	sub 	eax,rc.left
	
	mov 	ecx,rc.bottom
	sub 	ecx,rc.top
	
	.if 	(eax<541) || (ecx<430)
		invoke 	SetWindowPos,hMainWnd,HWND_TOP,0,0,541,430,SWP_NOMOVE
	.endif
	
	invoke 	GetClientRect,hMainWnd,ADDR rc
	
	; Button clean

	mov 	eax,rc.left
	add 	eax,rc.right
	sub 	eax,84
	mov 	left,eax

	
	mov 	eax,rc.top
	add 	eax,rc.bottom
	sub 	eax,100
	mov 	top,eax


	mov 	esi,SetWindowPos
	mov 	edi,GetDlgItem
	
	scall 	edi,hMainWnd,1015
	scall 	esi,eax,HWND_TOP,80,top,0,0,SWP_NOSIZE
	
	mov 	eax,rc.right
	sub 	eax,300
	
	scall 	esi,hMainTxtStatus,HWND_TOP,80+50,top,eax,17,0
	
	mov 	eax,rc.right
	sub 	eax,90
	add 	top,19
	scall 	esi,hMainEditPath,HWND_TOP,80,top,eax,17,0 
	
	add 	top,20
	
	scall 	edi,hMainWnd,1008
	scall 	esi,eax,HWND_TOP,80,top,0,0,SWP_NOSIZE
	
	scall 	edi,hMainWnd,1011
	scall 	esi,eax,HWND_TOP,80+99,top,0,0,SWP_NOSIZE
	
	sub 	left,80
	push 	top
	sub 	top,45
	scall 	esi,hTxtStatusClean,HWND_TOP,left,top,0,0,SWP_NOSIZE
	scall 	esi,hTxtStatusDetc,HWND_TOP,left,top,0,0,SWP_NOSIZE

	pop 	top
	add 	top,18
	scall 	edi,hMainWnd,1009
	scall 	esi,eax,HWND_TOP,80,top,0,0,SWP_NOSIZE
	
	scall 	edi,hMainWnd,1012
	scall 	esi,eax,HWND_TOP,80+99,top,0,0,SWP_NOSIZE
	
	mov 	eax,rc.right
	sub 	eax,rc.left
	sub 	eax,105
	mov 	left,eax
	
	scall 	edi,hMainWnd,1013
	scall 	esi,eax,HWND_TOP,left,top,0,0,SWP_NOSIZE
	add 	left,40
	scall 	edi,hMainWnd,1014
	scall 	esi,eax,HWND_TOP,left,top,0,0,SWP_NOSIZE

	mov 	eax,rc.right
	sub 	eax,rc.left
	sub 	eax,90
	add 	top,18
	scall 	esi,hMainProgBar,HWND_TOP,80,top,eax,20,0

	mov 	eax,rc.right
	sub 	eax,rc.left
	sub 	eax,90
	mov 	ecx,rc.bottom
	sub 	ecx,rc.top
	sub 	ecx,185
	scall 	esi,hMainList,HWND_TOP,80,75,eax,ecx,0
	
	m2m 	wt,rc.right
	cmp 	wt,541
	jb		@F
	sub 	wt,380
	invoke 	SendMessage,hMainList,LVM_SETCOLUMNWIDTH,1,wt ; last coloum
	jmp 	@nx
	@@:
	invoke 	SendMessage,hMainList,LVM_SETCOLUMNWIDTH,1,160 ; last coloum
	@nx:
	
	
	
	ret

RepositionMainWnd endp

align 16

HideAllStatus proc uses esi

	mov 	esi,ShowWindow

	scall 	esi,hTxtStatusClean,SW_HIDE
	scall 	esi,hTxtStatusDetc,SW_HIDE
	
	ret

HideAllStatus endp

align 16

MainWndTTLTimer proc

	inc 	TTLTimerCounter
	.if 	TTLTimerCounter == 30
		call 	HideAllStatus
		invoke 	KillTimer,hMainWnd,30001
	.endif

	ret

MainWndTTLTimer endp

align 16

SetStatusClrTtl proc

	mov 	TTLTimerCounter,0
	invoke 	SetTimer,hMainWnd,30001,50,ADDR MainWndTTLTimer
	
	ret

SetStatusClrTtl endp

align 16

BuildMainMenuPic proc uses esi ebx edi
	LOCAL 	hMenu:DWORD
	LOCAL 	hBmp:DWORD
	
	invoke 	GetMenu,hMainWnd
	.if 	eax
		mov 	hMenu,eax
		
		invoke 	LoadBitmap,hInstance,IMG_LOOP_SMALL
		mov 	hBmp,eax
		
		invoke 	SetBmpColor,eax
		mov 	esi,eax
		
		mov 	ebx,SetMenuItemBitmaps
		mov 	edi,hInstance
		
		scall 	ebx,hMenu,IDM_FILE_SCAN,MF_BYCOMMAND,esi,esi
		scall 	ebx,hMenu,IDM_FILE_SCANMULTIPLEOBJECT,MF_BYCOMMAND,esi,esi
		
		invoke 	LoadBitmap,edi,IMG_LOOP_SMALL2
		mov 	hBmp,eax
		invoke 	SetBmpColor,eax
		mov 	esi,eax
		scall 	ebx,hMenu,IDM_FILE_SCAN2,MF_BYCOMMAND,esi,esi
		
		invoke 	LoadBitmap,edi,IMG_MEMORY_SMALL
		mov 	hBmp,eax
		invoke 	SetBmpColor,eax
		mov 	esi,eax
		scall 	ebx,hMenu,IDM_FILE_SCANMEM,MF_BYCOMMAND,esi,esi
		
		invoke 	LoadBitmap,edi,IMG_SIKIL_SMALL
		mov 	hBmp,eax
		invoke 	SetBmpColor,eax
		mov 	esi,eax
		scall 	ebx,hMenu,IDM_FILE_EXIT,MF_BYCOMMAND,esi,esi
		
		invoke 	LoadBitmap,edi,IMG_PAPER_SMALL
		mov 	hBmp,eax
		invoke 	SetBmpColor,eax
		mov 	esi,eax
		scall 	ebx,hMenu,IDM_VIEW_RESULT,MF_BYCOMMAND,esi,esi
		
		invoke 	LoadBitmap,edi,IMG_BOOK_SMALL
		mov 	hBmp,eax
		invoke 	SetBmpColor,eax
		mov 	esi,eax
		scall 	ebx,hMenu,IDM_VIEW_VDB,MF_BYCOMMAND,esi,esi
		
		invoke 	LoadBitmap,edi,IMG_CONSOLE_SMALL
		mov 	hBmp,eax
		invoke 	SetBmpColor,eax
		mov 	esi,eax
		scall 	ebx,hMenu,IDM_VIEW_CONSOLELOG,MF_BYCOMMAND,esi,esi
		
		invoke 	LoadBitmap,edi,IMG_GEMBOK_SMALL
		mov 	hBmp,eax
		invoke 	SetBmpColor,eax
		mov 	esi,eax
		scall 	ebx,hMenu,IDM_VIEW_QUARZONE,MF_BYCOMMAND,esi,esi
		
		
		invoke 	LoadBitmap,edi,IMG_KUNCIINGGRIS_SMALL
		mov 	hBmp,eax
		invoke 	SetBmpColor,eax
		mov 	esi,eax
		scall 	ebx,hMenu,IDM_ADVANCED_CONFIG,MF_BYCOMMAND,esi,esi
		
		invoke 	LoadBitmap,edi,IMG_FIXED_SMAL
		mov 	hBmp,eax
		invoke 	SetBmpColor,eax
		mov 	esi,eax
		scall 	ebx,hMenu,IDM_FILE_SCANALLHARDISK,MF_BYCOMMAND,esi,esi
		
		invoke 	LoadBitmap,edi,IMG_REMOVABLE_SMALL
		mov 	hBmp,eax
		invoke 	SetBmpColor,eax
		mov 	esi,eax
		scall 	ebx,hMenu,IDM_FILE_SCANALLREM,MF_BYCOMMAND,esi,esi
		
		invoke 	LoadBitmap,edi,IMG_FOLDER
		mov 	hBmp,eax
		invoke 	SetBmpColor,eax
		mov 	esi,eax
		scall 	ebx,hMenu,IDM_FILE_SCANONLYWINDIR,MF_BYCOMMAND,esi,esi
		scall 	ebx,hMenu,IDM_FILE_SCANSYSDIR,MF_BYCOMMAND,esi,esi
		
		invoke 	LoadBitmap,edi,IMG_JEMPOL_SMALL
		mov 	hBmp,eax
		invoke 	SetBmpColor,eax
		mov 	esi,eax
		scall 	ebx,hMenu,IDM_VIEW_TRUSTZONE,MF_BYCOMMAND,esi,esi
		
		; ------- About menu ------- ;
		invoke 	LoadBitmap,edi,IMG_WARU_SMALL
		mov 	hBmp,eax
		invoke 	SetBmpColor,eax
		mov 	esi,eax
		scall 	ebx,hMenu,IDM_HELP_ABOUT,MF_BYCOMMAND,esi,esi
		
	.endif
	
	ret

BuildMainMenuPic endp

align 16

SetCtrlDS proc uses ebx esi edi lState:DWORD
	
	LOCAL 	hMenu:DWORD
	
	
	; ------- timer ------- ;
	.if 	lState
		call 	SetMainTimer
	.else
		call 	KillMainTimer
	.endif
	
	; ------- menu ------- ;
	invoke 	GetMenu,hMainWnd
	mov 	hMenu,eax
	.if 	lState
		mov 	ebx,MF_ENABLED
	.else
		mov 	ebx,MF_DISABLED or MF_GRAYED
	.endif
	
	mov 	esi,EnableMenuItem
	mov 	edi,hToolBar
	
	push ebp
	mov 	ebp,hMenu
	scall 	esi,ebp,IDM_FILE_SCAN,ebx
	scall 	esi,ebp,IDM_FILE_SCAN2,ebx
	scall 	esi,ebp,IDM_FILE_SCANALLHARDISK,ebx
	scall 	esi,ebp,IDM_FILE_SCANALLREM,ebx
	scall 	esi,ebp,IDM_FILE_SCANMULTIPLEOBJECT,ebx
	scall 	esi,ebp,IDM_VIEW_RESULT,ebx
	scall 	esi,ebp,IDM_VIEW_VDB,ebx
	scall 	esi,ebp,IDM_VIEW_QUARZONE,ebx
	scall 	esi,ebp,IDM_ADVANCED_CONFIG,ebx
	scall 	esi,ebp,IDM_HELP_INSTALL,ebx
	scall 	esi,ebp,IDM_FILE_SCANONLYWINDIR,ebx
	scall 	esi,ebp,IDM_FILE_SCANSYSDIR,ebx
	scall 	esi,ebp,IDM_VIEW_CLEARLIST,ebx
	scall 	esi,ebp,IDM_VIEW_TRUSTZONE,ebx
	scall 	esi,ebp,IDM_HELP_UPDATE,ebx
	scall 	esi,ebp,IDM_FILE_SCANMEM,ebx
	pop ebp
	
	; ------- toolbar ------- ;
	mov 	ebx,lState
	mov 	esi,SendMessage
	
	scall 	esi,edi,TB_ENABLEBUTTON,IDC_MAINTB_VIEWRES,ebx
	scall 	esi,edi,TB_ENABLEBUTTON,IDC_MAINTB_SCAN,ebx
	mov 	eax,lState
	
	RevEax
	
	scall 	esi,edi,TB_ENABLEBUTTON,IDC_MAINTB_STOP,eax
	
	; ------- is any plugins reached? ------- ;
	
	ret

SetCtrlDS endp

align 16

IsObjectExistsInList? proc uses esi lpszObject:DWORD
	LOCAL 	lvi:LV_ITEM
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	LOCAL 	retv:DWORD
	
	invoke 	MyZeroMemory,ADDR lBuff,MAX_PATH
	invoke 	MyZeroMemory,ADDR lvi,sizeof LV_ITEM
	mov 	retv,0
	
	mov 	esi,SendMessage
	
	mov 	[lvi.imask],LVIF_TEXT
	mov 	[lvi.iSubItem],1
	lea 	eax,lBuff
	mov 	[lvi.pszText],eax
	mov 	[lvi.cchTextMax],MAX_PATH
	
	scall 	esi,hMainList,LVM_GETITEMCOUNT,0,0
	
	test 	eax,eax
	jz 		@out
	xchg 	eax,ecx
	@lp:
		push 	ecx
		dec 	ecx
		mov 	[lvi.iItem],ecx
		
		lea 	eax,lvi
		scall 	esi,hMainList,LVM_GETITEM,0,eax
		
		invoke 	lstrcmpi,ADDR lBuff,lpszObject
		.if 	zero?
			mov 	retv,1
			add 	esp,4
			jmp 	@out
		.endif
		pop 	ecx
	loop 	@lp
	
@out:
	mov 	eax,retv
	ret

IsObjectExistsInList? endp

align 16

CheckAndAskIfAvailable proc

	mov 	ax,[LastScannedInfo.wStatus]
	cmp 	ax,STATUS_NOTTAKEACTION
	.if 	zero?
		mov 	eax,[LastScannedInfo.dwThreatsDetected]
		.if 	eax
			invoke 	MessageBox,hMainWnd,ADDR szYouHaveThreat,ADDR szAppName,MB_ICONQUESTION or MB_OKCANCEL
			.if 	eax == IDCANCEL
				return_0
			.endif
		.endif
	.endif
	return_1
	ret

CheckAndAskIfAvailable endp

align 16

IsArchiveRoot? proc  uses esi edi lItem:DWORD
	
	LOCAL 	lvi:LV_ITEM
	LOCAL 	lbuff[MAX_PATH+1]
	
	lea 	edi,lvi
	lea 	esi,lbuff
	
	invoke 	MyZeroMemory,edi,sizeof LV_ITEM
	invoke 	MyZeroMemory,esi,MAX_PATH
	
	mov 	[lvi.imask],LVIF_TEXT
	mov2 	[lvi.iItem],lItem
	mov 	[lvi.iSubItem],0
	mov 	[lvi.pszText],esi
	mov 	[lvi.cchTextMax],256
	invoke 	SendMessage,hMainList,LVM_GETITEM,0,edi
	
	.if 	byte ptr [esi]
		.while 	byte ptr [esi]!=' '
			inc 	esi
		.endw
		inc esi
		invoke 	lstrcmp,esi,reparg("Threat(s) inside")
		.if 	zero?
			return_1
		.endif
	.endif
	return_0
	ret

IsArchiveRoot? endp

align 16

MainPopMenu proc uses edi esi ebx
	
	LOCAL 	pt:POINT
	LOCAL 	state:DWORD
	
	lea 	edi,pt
	invoke 	MyZeroMemory,edi,sizeof POINT
	mov 	ebx,SendMessage
	mov 	esi,hMainList
	scall	ebx,esi,LVM_GETITEMCOUNT,0,0
	.if 	eax
		
		scall	ebx,esi,LVM_GETNEXTITEM,-1,LVNI_SELECTED
		mov 	state,eax
		scall	ebx,esi,LVM_GETITEMSTATE,eax,LVNI_SELECTED
		.if 	eax
			mov 	ebx,hMainPopMenu
			.if 	ebx
				
				align 4
				; ------- enable some item ------- ;
				mov 	esi,EnableMenuItem
				
				push 	edi
				
				.if 	InAction || InScanning
					mov 	edi,MF_DISABLED or MF_GRAYED
				.else
					mov 	edi,MF_ENABLED
				.endif
				
				invoke 	IsArchiveRoot?,state
				.if 	eax
					mov 	edi,MF_DISABLED or MF_GRAYED
					scall	esi,ebx,IDM_MPM_DELETE,MF_ENABLED
					scall	esi,ebx,IDM_MPM_SIGNASTRUST,edi
				.else
					scall	esi,ebx,IDM_MPM_DELETE,edi
					
					invoke 	IsItemInsideArc,state
					.if 	eax
						scall	esi,ebx,IDM_MPM_SIGNASTRUST,MF_DISABLED or MF_GRAYED
					.else
						scall	esi,ebx,IDM_MPM_SIGNASTRUST,MF_ENABLED
					.endif
					
				.endif
				
				scall 	esi,ebx,IDM_MPM_CLEAN,edi
				scall	esi,ebx,IDM_MPM_PROPERTIES,MF_ENABLED
				scall	esi,ebx,IDM_MPM_QUARANTINE,edi
				scall	esi,ebx,IDM_MPM_GOTOOBJL,MF_ENABLED
				scall	esi,ebx,IDM_MPM_COPYTHREATN,MF_ENABLED
				scall	esi,ebx,IDM_MPM_COPYOBJPATH,MF_ENABLED
				
				pop 	edi
				
				align 4
				
				invoke 	GetCursorPos,edi
				sub 	[edi.POINT].x,20
				invoke	TrackPopupMenu,ebx,TPM_LEFTALIGN,[edi.POINT].x,[edi.POINT].y,0,hMainWnd,0
			.endif
		.else
			
			align 4
			mov 	ebx,hMainPopMenu
			; ------- disable some item ------- ;
			mov 	esi,EnableMenuItem
			scall 	esi,ebx,IDM_MPM_CLEAN,MF_DISABLED or MF_GRAYED
			scall	esi,ebx,IDM_MPM_DELETE,MF_DISABLED or MF_GRAYED
			scall	esi,ebx,IDM_MPM_PROPERTIES,MF_DISABLED or MF_GRAYED
			scall	esi,ebx,IDM_MPM_QUARANTINE,MF_DISABLED or MF_GRAYED
			scall	esi,ebx,IDM_MPM_GOTOOBJL,MF_DISABLED or MF_GRAYED
			scall	esi,ebx,IDM_MPM_SIGNASTRUST,MF_DISABLED or MF_GRAYED
			scall	esi,ebx,IDM_MPM_COPYTHREATN,MF_DISABLED or MF_GRAYED
			scall	esi,ebx,IDM_MPM_COPYOBJPATH,MF_DISABLED or MF_GRAYED						
			align 4
			
			invoke 	GetCursorPos,edi
			sub 	[edi.POINT].x,20
			invoke	TrackPopupMenu,ebx,TPM_LEFTALIGN,[edi.POINT].x,[edi.POINT].y,0,hMainWnd,0
		.endif
	.endif

	ret

MainPopMenu endp

align 16

ObjectProperties proc uses esi
	
	LOCAL 	lvi:LV_ITEM
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	
	invoke 	MyZeroMemory,ADDR lvi,sizeof LV_ITEM
	invoke 	MyZeroMemory,ADDR lBuff,MAX_PATH
	
	mov 	esi,SendMessage
	
	mov 	ebx,hMainList
	scall 	esi,ebx,LVM_GETNEXTITEM,-1,LVNI_SELECTED
	mov 	[lvi.imask],LVIF_TEXT
	mov 	[lvi.iItem],eax
	inc 	[lvi.iSubItem]
	lea 	eax,lBuff
	mov 	[lvi.pszText],eax
	mov 	lvi.cchTextMax,MAX_PATH
	
	lea 	eax,lvi
	scall 	esi,ebx,LVM_GETITEM,0,eax
	
	
	ret

ObjectProperties endp

align 16

GotoObjectLocation proc uses edi
	
	LOCAL lBuff[MAX_PATH+1]:BYTE
	
	lea 	edi,lBuff
	invoke 	MyZeroMemory,edi,MAX_PATH
	
	invoke 	SendMessage,hMainList,LVM_GETNEXTITEM,-1,LVNI_SELECTED
	invoke 	GetObjectPath,edi,eax	
	.if 	byte ptr [edi]
		invoke 	OnlyPathDir,edi
		invoke 	ShellExecute,hMainWnd,offset szOpen,edi,0,0,SW_SHOWDEFAULT
	.endif
	
	ret

GotoObjectLocation endp

align 16

SelectAllObject proc uses ebx

    LOCAL lvi:LV_ITEM
    LOCAL lCount:DWORD

	mov 	ebx,SendMessage
    scall 	ebx,hMainList,LVM_GETITEMCOUNT,0,0
    mov 	lCount,eax
    
    .WHILE lCount != -1
        mov 	[lvi.imask],LVIF_STATE
        mov 	[lvi.state],LVIS_SELECTED OR LVIS_FOCUSED
        m2m 	[lvi.stateMask],LVIS_SELECTED OR LVIS_FOCUSED
        lea 	eax,lvi
        scall 	ebx,hMainList,LVM_SETITEMSTATE,lCount,eax
        dec 	lCount
    .ENDW

    ret

SelectAllObject endp

align 16

SetMenuInstallable proc
	
	LOCAL ovi:OSVERSIONINFO
	
	invoke MyZeroMemory,ADDR ovi,sizeof OSVERSIONINFO
	
	mov 	[ovi.dwOSVersionInfoSize],sizeof OSVERSIONINFO
	
	invoke 	GetVersionEx,ADDR ovi
	
	.if 	[ovi.dwMajorVersion]==5 && \; ------- Windows XP ------- ;
			[ovi.dwMinorVersion]==1
			invoke 	EnableMenuItem,hMainMenu,IDM_HELP_INSTALL,MF_BYCOMMAND or MF_ENABLED
	.elseif [ovi.dwMajorVersion]==5 && \; ------- Windows 2000 ------- ;
			[ovi.dwMinorVersion]==0
		call @setnone
	.else
		call @setnone	
	.endif
	
	ret
@setnone:
invoke 	EnableMenuItem,hMainMenu,IDM_HELP_INSTALL,MF_BYCOMMAND or MF_DISABLED or MF_GRAYED
	retn
SetMenuInstallable endp

align 16

.data
	tmrCapBuff db 256 dup(0)
	CapASeted dd 0
.code

tmrCapPercent proc
	
	LOCAL 	wndl:WINDOWPLACEMENT
	
	push 	esi
	lea 	esi,wndl
	invoke 	MyZeroMemory,esi,sizeof WINDOWPLACEMENT
	
	invoke 	GetWindowPlacement,hMainWnd,esi
	
	.if 	[esi.WINDOWPLACEMENT].showCmd == SW_SHOWMINIMIZED
	    invoke 	PercentThis,MainPBPos,AllFilesCount
	    .if 	eax!=LastPercentValue
			invoke 	wsprintf,offset tmrCapBuff,reparg("%d%% Completed"),eax
			invoke 	SetWindowText,hMainWnd,offset tmrCapBuff
			mov 	CapASeted,0
		.endif
	.else
		.if 	!CapASeted
			mov 	CapASeted,1
			invoke 	SetWindowText,hMainWnd,offset szAppName
		.endif
	.endif
	
	.if 	!InScanning
		invoke 	KillTimer,hMainWnd,1234
		invoke 	SetWindowText,hMainWnd,offset szAppName 
	.endif
	
	pop esi
	ret

tmrCapPercent endp

align 16






