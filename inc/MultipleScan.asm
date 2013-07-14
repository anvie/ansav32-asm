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


; ------- MultipleScan.asm ------- ;

.data?
	IDC_LIST_MULTISCANOBJ 	equ 1001
	IMG_FILEFOLDER			equ 703
	IDC_TXT_READYTO			equ 1007

	hMultiScanDlg 			dd ?
	hListMultiScan 			dd ?
	hImgFileFolder			dd ?
	hBmpFileFolder 			dd ?
	hMultiScanCtrlScan		dd ?
.data
	szMultiObjectReadyF		db 'Object : %d file(s) and %d directorie(s), ready to scan.',0
	szMultiObjectReady0		db 'Object : 0 file(s) and 0 directorie(s).',0
.code

InsertMultiObjectToList proc lpszObject:DWORD,iImage:DWORD
	LOCAL 	lvi:LV_ITEM
	
	invoke 	MyZeroMemory,ADDR lvi,sizeof LV_ITEM
	
	mov 	[lvi.imask],LVIF_TEXT or LVIF_IMAGE
	m2m 	[lvi.pszText],lpszObject
	mov 	[lvi.cchTextMax],256
	m2m 	[lvi.iImage],iImage
	invoke 	SendMessage,hListMultiScan,LVM_GETITEMCOUNT,0,0
	mov 	[lvi.iItem],eax
	invoke 	SendMessage,hListMultiScan,LVM_INSERTITEM,0,ADDR lvi
	
	ret

InsertMultiObjectToList endp

align 16

BuildListMultiScan proc
	
	
    INVOKE  SendMessage, hListMultiScan, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, \
                         LVS_EX_SUBITEMIMAGES or LVS_EX_GRIDLINES or \
                         LVS_EX_FULLROWSELECT
	invoke 	ImageList_Create,16,16,16,4,0
	mErrorTrap	eax,"Cannot create img list for hImgFileFolder, in BuildListMultiScan",@endl
	mov 	hImgFileFolder,eax
	
	invoke 	LoadBitmap,hInstance,IMG_FILEFOLDER
	mErrorTrap 	eax,"Cannot load bitmap for res ID 703 (IMG_FILEFOLDER)",@nobmp
	mov 	hBmpFileFolder,eax
	
	invoke 	ImageList_Add,hImgFileFolder,eax,0
	invoke 	SendMessage,hListMultiScan,LVM_SETIMAGELIST,LVSIL_SMALL,hImgFileFolder
	
	invoke 	LvInsertColoumn,hListMultiScan,reparg("Object"),0,395,0

	call 	RenewMultipleObjectScanCount

	invoke 	SetLastError,0
	
	jmp 	@endl
	@nobmp:
	invoke 	ImageList_Destroy,hImgFileFolder
	
	@endl:
	ret

BuildListMultiScan endp

align 16

; ------- dialog proc for Multiple scan object ------- ;
MultipleScanDlgProc proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	
	mov 	eax,uMsg
	.if 	eax 	== WM_INITDIALOG
		m2m 	hMultiScanDlg,hWin
		
		.if 	TimeForBlind
			invoke 	MakeRandomString,ADDR szRandomString,10
			invoke 	SetWindowText,hWin,ADDR szRandomString 
		.endif
		
		invoke 	SendMessage,hWin,WM_SETICON,ICON_SMALL,hMainIcon
		
		invoke 	GetDlgItem,hWin,IDC_LIST_MULTISCANOBJ
		mov 	hListMultiScan,eax
		invoke 	GetDlgItem,hWin,1008
		mov 	hMultiScanCtrlScan,eax
		
		call 	BuildListMultiScan
		invoke 	SetFocus,hWin
	.elseif 	eax == WM_COMMAND
		
		mov 	eax,wParam
		and 	eax,0FFFFh
		.if 	eax == 1004		; <-- Close/Cancel ;
			jmp 	@close
		.elseif 	eax == 1002 		; <-- Add file(s) ;
			call 	InsertMultiObjectFile
		.elseif 	eax == 1003 		; <-- Add directorie(s) ;
			call 	InsertMultiObjectDir
		.elseif 	eax == 1009		; <-- Clear list ;
			invoke 	SendMessage,hListMultiScan,LVM_DELETEALLITEMS,0,0
			call 	RenewMultipleObjectScanCount
		.elseif 	eax == 1008 		; <-- Scan ;
			call 	StartProcessScanAllObjectList
		.elseif 	eax == 1010		; <-- Always on top ;
			invoke	TopNoTop,hWin,eax 
		.endif
	.elseif 	eax == WM_DROPFILES
		push 	[wParam]
		call	MultipleScanDropFiles
	.elseif 	eax == WM_CLOSE
	@close:
		call 	MultipleScanObjectCleanUp
		invoke 	DestroyWindow,hWin
		invoke 	SetForegroundWindow,hMainWnd
		invoke 	SetFocus,hMainWnd
	.endif
	
@endl:
	xor	eax,eax
	ret

MultipleScanDlgProc endp

align 16

MultipleScanObject proc uses ebx
	

	mov 	ebx,hMultiScanDlg
	invoke 	IsWindow,ebx
	.if 	eax
		invoke 	ShowWindow,ebx,SW_RESTORE
		invoke 	SetForegroundWindow,ebx
		invoke 	SetFocus,ebx
		invoke 	FlashWindow,ebx,1
	.else
		invoke 	CreateDialogParam,hInstance,IDD_MULTIPLEOBJECTSCAN,0,ADDR MultipleScanDlgProc,0
		mErrorTrap	eax,"Cannot CreateDialogParam for res ID IDD_MULTIPLEOBJECTSCAN, in MultipleScanObject",0
	.endif
	
	ret

MultipleScanObject endp

align 16

MultipleScanObjectCleanUp proc
	
	.if 	hImgFileFolder
		invoke 	ImageList_Destroy,hImgFileFolder
	.endif
	.if 	hBmpFileFolder
		invoke 	DeleteObject,hBmpFileFolder
	.endif
	
	ret

MultipleScanObjectCleanUp endp

align 16

MultipleScanDropFiles proc uses ebx wParam:DWORD
	
	LOCAL 	fNum:DWORD
	
		push 	edi
		valloc 	MAX_PATH+1
		mErrorTrap eax,"Cannot allocate memory for query drag file(s)",@merr
		mov 	edi,eax
		
		mov 	[fNum],0
		invoke 	DragQueryFile,[wParam],-1,edi,MAX_PATH
		mov 	[fNum],eax
		
		xor 	ebx,ebx
		@nxfile:
			invoke 	DragQueryFile,[wParam],ebx,edi,MAX_PATH
			test 	eax,eax
			jz 		@endl
			.if 	byte ptr [edi]
				
				invoke 	GetFileAttributes,edi
				xor 	ecx,ecx
				.if 	!(ax & FILE_ATTRIBUTE_DIRECTORY)
					inc ecx
				.endif
				invoke 	InsertMultiObjectToList,edi,ecx
				
				call 	RenewMultipleObjectScanCount
			.endif
			inc		ebx
			cmp 	ebx,[fNum]
		jb	@nxfile
		
		vfree 	edi
		pop 	edi
	@merr:
@endl:
	ret

MultipleScanDropFiles endp

align 16

InsertMultiObjectFile proc uses edi esi
	LOCAL 	of:OPENFILENAME
	LOCAL 	fNameArr,len:DWORD
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	
	invoke 	MyZeroMemory,ADDR of,sizeof OPENFILENAME
	invoke 	MyZeroMemory,ADDR lBuff,MAX_PATH
	
	valloc 	((MAX_PATH*256)+1)
	mErrorTrap 	eax,"Cannot allocate memory for get multiple file object to scan, in InsertMultiObjectFile",@endl
	mov 	fNameArr,eax
	
	mov 	[of.lStructSize],sizeof OPENFILENAME
	m2m 	[of.hwndOwner],hMultiScanDlg
	m2m 	[of.hInstance],hInstance
	mov 	[of.lpstrFile],eax
	.if 	!TimeForBlind
		lea 	eax,szMaskAllFile
	.else
		invoke 	MakeRandomString,ADDR szRandomString,5
		lea 	eax,szRandomString
	.endif	
	mov 	[of.lpstrFilter],eax
	mov 	[of.nMaxFile],256
	mov 	[of.Flags],200h or 80000h
	invoke 	GetOpenFileName,ADDR of
	.if 	eax
		mov 	edi,fNameArr
		.if 	byte ptr [edi]
			
			; ------- process array ------- ;
			invoke 	GetFileAttributes,edi
			.if 	!(eax & FILE_ATTRIBUTE_DIRECTORY)
				; insert single file
				invoke 	InsertMultiObjectToList,edi,1
			.else
				; insert multiple file
				lea 	esi,lBuff
				invoke 	lstrcpyn,esi,edi,MAX_PATH
				invoke 	TruePath,esi
				cld
				xor 	al,al
				mov 	ecx,-1
				repnz 	scasb
				neg 	ecx
				dec 	ecx
				mov 	len,ecx
				@lp:
					mov 	ecx,len
					mov 	byte ptr [esi+ecx],0
					invoke 	lstrcat,esi,edi
					invoke 	InsertMultiObjectToList,esi,1
				NextArray 	@lp
			.endif
			
			; ------- Renew count state ------- ;
			call 	RenewMultipleObjectScanCount
			
		.endif
	.endif
	vfree 	fNameArr
	
@endl:
	ret

InsertMultiObjectFile endp

align 16

InsertMultiObjectDir proc
	
	
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	
	
	invoke 	MyZeroMemory,ADDR lBuff,MAX_PATH
	
	invoke 	BrowseForFolder,hMultiScanDlg,ADDR lBuff,ADDR szAppName,reparg("Choose directory..."),0
	lea 	eax,lBuff
	.if 	byte ptr [eax]
		
		invoke 	InsertMultiObjectToList,eax,0
		call 	RenewMultipleObjectScanCount
	.endif
	
	ret

InsertMultiObjectDir endp

align 16

RenewMultipleObjectScanCount proc
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	LOCAL 	Dirs,Files:DWORD
	LOCAL 	lvi:LV_ITEM
	
	invoke 	MyZeroMemory,ADDR lBuff,sizeof MAX_PATH
	invoke 	MyZeroMemory,ADDR lvi,sizeof LV_ITEM
	mov 	Dirs,0
	mov 	Files,0
	
	invoke 	SendMessage,hListMultiScan,LVM_GETITEMCOUNT,0,0
	.if 	!eax
		invoke 	SetDlgItemText,hMultiScanDlg,IDC_TXT_READYTO,ADDR szMultiObjectReady0
		invoke 	EnableWindow,hMultiScanCtrlScan,FALSE
		jmp 	@endl
	.endif
	xchg 	ecx,eax
	mov 	[lvi.imask],LVIF_TEXT
	lea 	eax,lBuff
	mov 	[lvi.pszText],eax
	mov 	[lvi.cchTextMax],MAX_PATH
	@lp:
		push 	ecx
		dec 	ecx
		mov 	[lvi.iItem],ecx
		invoke 	SendMessage,hListMultiScan,LVM_GETITEM,0,ADDR lvi
		invoke 	GetFileAttributes,ADDR lBuff
		.if 	ax & FILE_ATTRIBUTE_DIRECTORY
			inc 	Dirs
		.else
			inc 	Files
		.endif
		pop 	ecx
	loop 	@lp
	invoke 	wsprintf,ADDR lBuff,ADDR szMultiObjectReadyF,Files,Dirs
	invoke 	SetDlgItemText,hMultiScanDlg,IDC_TXT_READYTO,ADDR lBuff
	invoke 	EnableWindow,hMultiScanCtrlScan,TRUE
@endl:
	ret
RenewMultipleObjectScanCount endp

align 16

; ------- thread ------- ;
ProcessScanAllObjectList proc uses esi edi ebx lParam:DWORD

	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	LOCAL 	lvi:LV_ITEM
	
	; ------- seh installation ------- ;
	SehBegin 	_psabl
	
	
	invoke 	MyZeroMemory,ADDR lBuff,sizeof MAX_PATH
	invoke 	MyZeroMemory,ADDR lvi,sizeof LV_ITEM
	
	invoke 	SetCtrlDS,STATE_DISABLE
	invoke 	SetActionTbState,STATE_DISABLE
	
	mov 	edi,AppendLogConsole
	scall 	edi,reparg("Scan started uses multiple selected object")
	scall 	edi,offset szInitSLS
	; ------- init scan ------- ;
	call 	InitScan
	
	; ------- prepare buffer for last scanned path ------- ;
	call 	InitLastScannedBuffer
	call 	SetAllMainCtrlState
	
	scall 	edi,offset szBuffering
	StatusBuffering 	; <-- Set status ;

	align 4
	
	mov 	esi,SendMessage

	; ------- populate progbar ------- ;
	scall 	esi,hListMultiScan,LVM_GETITEMCOUNT,0,0
	.if 	eax
		mov 	ecx,eax
		mov 	ebx,eax
		mov 	[lvi.imask],LVIF_TEXT
		lea 	eax,lBuff
		mov 	[lvi.pszText],eax
		mov 	[lvi.cchTextMax],MAX_PATH
		
		
		@lp:
			push 	ecx
			dec 	ecx
			mov 	[lvi.iItem],ecx
			lea 	eax,lvi
			scall 	esi,hListMultiScan,LVM_GETITEM,0,eax
			lea 	eax,lBuff
			.if 	byte ptr [eax]
				invoke 	GetFileAttributes,ADDR lBuff
				.if 	ax & FILE_ATTRIBUTE_DIRECTORY
					lea 	eax,lBuff
					push 	eax
					call 	GetAllFilesCountFromThisPath
				.else
					inc 	AllFilesCount
				.endif
			.endif
			
			pop 	ecx
		loop 	@lp
		scall 	esi,hMainProgBar,PBM_SETRANGE32,0,AllFilesCount
		scall 	edi,offset szDone
		scall 	edi,offset szChecking
		
		align 4
		; ------- processing ------- ;
		StatusChecking
		mov 	ecx,ebx
		@lp2:
			push 	ecx
			dec 	ecx
			mov 	[lvi.iItem],ecx
			lea 	eax,lvi
			scall 	esi,hListMultiScan,LVM_GETITEM,0,eax
			lea 	eax,lBuff
			.if 	byte ptr [eax]
				invoke 	GetFileAttributes,ADDR lBuff
				.if 	!ax & FILE_ATTRIBUTE_DIRECTORY
					scall 	edi,offset szCheckThisDir
					lea 	eax,lBuff 
					scall 	edi,eax
					invoke 	CheckThisPath,ADDR lBuff
				.else
					scall 	edi,offset szCheckThisFile
					lea 	eax,lBuff
					scall 	edi,eax
					invoke 	CheckThisFile,ADDR lBuff,ADDR gTFI ;,0
					.if 	eax
						invoke 	LvInsertTFIItem,ADDR gTFI
						inc 	DetectedThreatsCnt
						invoke 	wsprintf,ADDR szDetectedThreatCntBuff,ADDR szdTosF,DetectedThreatsCnt
						invoke 	SetWindowText,hTxtDetectedThreats,ADDR szDetectedThreatCntBuff
					.endif
				.endif
				.if 	!StopScan
					invoke 	InsertLastScannedPathBuffer,ADDR lBuff
				.endif
			.endif
			pop 	ecx
			dec 	ecx
			jecxz 	@F
		jmp 	@lp2
		@@:
		
		scall 	edi,offset szFlushBuffer
		invoke 	SaveResult,reparg("Multiple object scan")
		.if 	StopScan
			invoke 	SetDlgItemText,hMainWnd,IDC_EDIT_PATH,ADDR szCheckStoped
			scall 	esi,hMainProgBar,PBM_SETPOS,0,0
		.else
			invoke 	SetDlgItemText,hMainWnd,IDC_EDIT_PATH,ADDR szCheckComplete
			scall 	esi,hMainProgBar,PBM_SETPOS,AllFilesCount,0
		.endif
		
		align 4
		
		mov 	StopScan,1
		StatusIdleWait 		; <-- Set status ;
		
		mov 	ebx,SetMainTxtStatus
		
		.if 	DetectedThreatsCnt
			scall 	ebx,STATUS_DETECTED
			invoke 	SetActionTbState,STATE_ENABLE
			scall 	edi,offset szCheckCmpltDC
		.else
			scall 	ebx,STATUS_CLEAN
			invoke 	SetActionTbState,STATE_DISABLE
			scall 	edi,offset szCheckCmpltNDC
		.endif
		
	.else
		StatusIdle		; <-- Set status ;
		ViewError 	hMultiScanDlg,"Some error was occured!"
	.endif
	
	
	; ------- seh trapper ------- ;
	SehTrap 	_psabl
		ErrorDump 	"ProcessScanAllObjectList",offset ProcessScanAllObjectList,offset szUtilsasm
	SehEnd 		_psabl
	
	scall 	edi,offset szScanLogReady
	
	invoke 	SetCtrlDS,STATE_ENABLE
	scall 	esi,hMultiScanDlg,WM_CLOSE,0,0
	invoke 	ExitThread,0
	
	ret

ProcessScanAllObjectList endp

align 16

StartProcessScanAllObjectList proc uses esi ebx
	
	LOCAL 	wp:WINDOWPLACEMENT
	LOCAL 	thID:DWORD

	mov 	esi,ShowWindow
	mov 	ebx,hMainWnd

	scall 	esi,hMultiScanDlg,SW_HIDE
	invoke 	GetWindowPlacement,ebx,ADDR wp
	.if 	!([wp.showCmd] & WS_MINIMIZE)
		scall 	esi,ebx,SW_RESTORE
	.else
		scall 	esi,ebx,[wp.showCmd]
	.endif
	
	invoke 	SetForegroundWindow,ebx
	invoke 	SetFocus,ebx
	
	invoke 	SendMessage,hMainList,LVM_DELETEALLITEMS,0,0
	invoke 	CreateThread,0,0,ADDR ProcessScanAllObjectList,0,0,ADDR thID
	invoke 	CloseHandle,eax
	

	ret

StartProcessScanAllObjectList endp

align 16





