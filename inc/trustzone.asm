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

;-------------------------------------- trustzone.asm ----------------------------------------;

IDC_LISTTRUSTZONE 	equ 1001

.data?

	TRUSTFILE struct
		szFileName db MAX_PATH-30 dup(?)
		FileSize dd ?
		crcSize dd ?
		dwCrc32	dd ?
	TRUSTFILE ends

	hTrustZoneWnd dd ?
	
	TrustDatabase dd ?
	TrustDatabaseSize dd ?
	
.data
	szTrustzoneasm db "trustzone.asm"
	szTrusZoneDescription 	db "These object(s) listed bellow will be skiped during scanning.",13,10
							db "Please only add for a good trusted file.",0

.code

align 16

LoadTrustDatabase proc uses esi edi ebx
	
	; ------- seh installation ------- ;
	SehBegin 	__ltd
	
	
	.if 	TrustDatabase
		SehPop
		return_0
	.endif
	
	invoke 	CreateFile,offset szTrustDataPath,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	.if 	eax!=-1
		mov 	esi,eax
		invoke 	GetFileSize,esi,0
		mov 	ebx,eax
		.if 	eax
			add 	eax,4	; <-- careful ;
			mov 	TrustDatabaseSize,eax
			valloc eax
			.if 	eax
				mov edi,eax
				
				invoke 	ReadFile,esi,edi,ebx,ADDR brw,0
				.if 	!eax
					vfree edi
					ViewError	hTrustZoneWnd,"Cannot load trust database, read error."
				.endif
				mov 	TrustDatabase,edi
			.endif
		.endif
		invoke 	CloseHandle,esi
	.endif
	
	; ------- seh trapper ------- ;
	SehTrap 	__ltd
		ErrorDump 	"LoadTrustDatabase",offset LoadTrustDatabase,offset szTrustzoneasm
	SehEnd 		__ltd
	
	ret

LoadTrustDatabase endp

align 16

UnLoadTrustDatabase proc

	mov eax,TrustDatabase
	.if 	eax
		vfree 	eax
		mov 	TrustDatabase,0
		mov 	TrustDatabaseSize,0
	.endif

	ret
UnLoadTrustDatabase endp

align 16

IsTrusted proc uses edi esi iBase:DWORD,iSize:DWORD
	
	LOCAL 	retv:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__it
	
	mov 	edi,TrustDatabase
	.if 	!edi
		SehPop
		return_0
	.endif
	
	mov 	retv,0
	
	assume 	edi:ptr TRUSTFILE
	mov 	esi,iBase
	.while 	byte ptr [edi]
		mov 	ecx,iSize
		cmp 	ecx,[edi].FileSize
		jb		@nx
		mov 	eax,[edi].crcSize
		cmp 	ecx,eax
		jb 		@nx
		
		push 	eax
		push 	esi
		call	crcCalc
		.if 	eax==[edi].dwCrc32
			mov 	retv,1
			jmp 	@break
		.endif
		@nx:
		add 	edi,sizeof TRUSTFILE
	.endw	
@break:
	assume 	edi:nothing
	
	; ------- seh trapper ------- ;
	SehTrap 	__it
		ErrorDump 	"IsTrusted",offset IsTrusted,offset szTrustzoneasm
	SehEnd 		__it
	
	mov 	eax,retv
	ret

IsTrusted endp

align 16

ReloadTrustDatabase proc
	
	call 	UnLoadTrustDatabase
	mov 	TrustDatabase,0
	call 	LoadTrustDatabase
	
	ret

ReloadTrustDatabase endp

align 16

RenewTrustListItem proc uses esi edi ebx
	
	; ------- seh installation ------- ;
	SehBegin 	__rtli
	
	invoke 	GetDlgItem,hTrustZoneWnd,1001
	mov esi,eax
	invoke 	SendMessage,esi,LB_RESETCONTENT,0,0
	mov edi,TrustDatabase
	.if 	!edi
		call 	SetTrustZoneState
		SehPop
		return_0
	.endif
	xor ebx,ebx
	.while 	byte ptr [edi]
		invoke 	SendMessage,esi,LB_ADDSTRING,ebx,edi
		add 	edi,sizeof TRUSTFILE
	.endw

	; ------- Seh trapper ------- ;
	SehTrap 	__rtli
		ErrorDump 	"RenewTrustListItem",offset RenewTrustListItem,offset szTrustzoneasm
	SehEnd 		__rtli
	
	call 	SetTrustZoneState
	ret

RenewTrustListItem endp

align 16

AddFileSignToTrustDatabase proc	uses edi tf:DWORD
	
	LOCAL 	hFile,first:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__afsttd

	mov 	edi,offset szTrustDataPath
	invoke 	FileExist,edi
	.if 	eax
		mov 	eax,OPEN_EXISTING
		mov 	first,0
	.else
		mov 	eax,CREATE_ALWAYS
		mov 	first,1
	.endif
	invoke 	CreateFile,edi,GENERIC_READ or GENERIC_WRITE, \
			FILE_SHARE_READ or FILE_SHARE_WRITE, \
			0,eax,FILE_ATTRIBUTE_NORMAL,0
	.if 	eax!=-1
		mov 	hFile,eax
		
		mov edi,tf
		.if 	!first
			invoke 	SetFilePointer,hFile,0,0,FILE_END
		.endif
		
		invoke 	WriteFile,hFile,edi,sizeof TRUSTFILE,ADDR brw,0
		.if 	!eax
			ViewError	hTrustZoneWnd, \
			"Cannot update trust zone database, write error"
		.endif
		
		invoke 	CloseHandle,hFile
	.else
		ViewError	hTrustZoneWnd,"Cannot open trust database file to add."
	.endif

	; ------- seh trapper ------- ;
	SehTrap 	__afsttd
		ErrorDump	"AddFileSignToTrustDatabase",offset AddFileSignToTrustDatabase,offset szTrustzoneasm
	SehEnd 		__afsttd

	
	ret

AddFileSignToTrustDatabase endp

align 16

AddFileToTrustDB proc uses esi ebx edi lpszFilePath:DWORD,pMem:DWORD,pSize:DWORD,fRealSize:DWORD,isfile:DWORD
	
	LOCAL 	tf:TRUSTFILE
	
	lea 	ebx,tf
	invoke 	MyZeroMemory,ebx,sizeof TRUSTFILE
	
	mov 	esi,pMem
	
	; ------- crc32 ------- ;
	push 	pSize
	push 	esi
	call 	crcCalc
	
	mov 	[ebx.TRUSTFILE].dwCrc32,eax
	mov2 	[ebx.TRUSTFILE].FileSize,fRealSize
	mov2 	[ebx.TRUSTFILE].crcSize,pSize
	lea 	eax,[ebx.TRUSTFILE].szFileName
	
	.if 	isfile
		invoke 	OnlyFileName,eax,lpszFilePath
	.else
		invoke 	lstrcpyn,eax,lpszFilePath,MAX_PATH
	.endif
	
	invoke 	AddFileSignToTrustDatabase,ebx
	
	call 	ReloadTrustDatabase
	call 	RenewTrustListItem
	ret

AddFileToTrustDB endp

align 16

AddFileToTrustDBraw proc uses edi esi lpFile:DWORD,isfile:DWORD
	
	LOCAL 	hFile,fSize:DWORD
	LOCAL 	fRealSize:DWORD
	
	
	invoke 	CreateFile,lpFile, \
			GENERIC_READ,FILE_SHARE_READ \
			,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	.if 	eax && eax != -1
		mov 	hFile,eax
		
		invoke 	GetFileSize,eax,0
		.if 	eax
			mov 	fSize,eax
			mov 	fRealSize,eax
			
			.if 	fSize>400h
				mov 	fSize,400h
			.endif
			
			valloc 	fSize
			.if 	eax
				mov 	edi,lpFile
				mov 	esi,eax
				
				invoke 	ReadFile,hFile,esi,fSize,ADDR brw,0
				.if 	eax
					
					invoke 	AddFileToTrustDB,edi,esi,fSize,fRealSize,isfile
					
				.else
					ViewError	hTrustZoneWnd,"Cannot read file."
				.endif
				
				vfree 	esi
			.else
				ViewError	hTrustZoneWnd,"Cannot allocate memory." 
			.endif
		.else
			ViewError	hTrustZoneWnd,"Not support zero size file."
		.endif
		
		invoke 	CloseHandle,hFile
	.else
		ViewError	hTrustZoneWnd,"Cannot open file."
	.endif
	ret

AddFileToTrustDBraw endp

align 16

AddFileToTrustZone proc uses edi esi ebx
	
	LOCAL 	ofn:OPENFILENAME
	LOCAL 	szFile[MAX_PATH]:BYTE
	LOCAL 	szParentPath[MAX_PATH]:BYTE
	LOCAL 	tmp,tmp2,isfile:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__aftfz
	
	lea 	edi,ofn
	invoke 	MyZeroMemory,edi,sizeof OPENFILENAME
	
	lea 	esi,szFile
	invoke 	MyZeroMemory,esi,MAX_PATH
	invoke 	MyZeroMemory,ADDR szParentPath,MAX_PATH
	
	mov 	[ofn.lStructSize],sizeof OPENFILENAME
	mov2 	[ofn.hwndOwner],hTrustZoneWnd
	mov2 	[ofn.hInstance],hInstance
	mov 	[ofn.lpstrFilter],offset szMaskAllFile
	mov 	[ofn.nMaxFile],256
	mov 	[ofn.lpstrTitle],reparg("Choose file...")
	mov 	[ofn.lpstrFile],esi
	mov 	[ofn.Flags],OFN_ALLOWMULTISELECT or \
			OFN_EXPLORER or OFN_FILEMUSTEXIST or \
			OFN_NOLONGNAMES or OFN_READONLY
	
	invoke 	GetOpenFileName,edi
	.if 	!byte ptr [esi] && !eax
		SehPop
		return_0
	.endif
	
	mov 	isfile,0
	invoke 	GetFileAttributes,esi
	.if 	(eax & FILE_ATTRIBUTE_DIRECTORY)
		lea 	edi,szParentPath
		invoke 	lstrcpyn,edi,esi,MAX_PATH
		invoke 	TruePath,edi
		invoke 	lstrlen,edi
		mov 	tmp,eax
		add 	tmp,edi
	.else
		mov 	isfile,1
	.endif
	
	; ------- ADD IT ------- ;
	.if 	!isfile
		lea 	esi,[esi+eax]
		invoke 	lstrcat,ADDR szParentPath,esi
	.endif
	
	call 	crcInit
	
	.while 	byte ptr [esi]
		.if 	isfile
			mov 	eax,esi
		.else
			lea 	eax,szParentPath
		.endif
		
		invoke 	AddFileToTrustDBraw,eax,isfile
		
		.if 	!isfile
			mov esi,edi
			.while byte ptr [esi]
				inc 	esi
			.endw
			inc 	esi
			mov 	eax,tmp
			mov 	byte ptr [eax],0
			invoke 	lstrcat,ADDR szParentPath,esi
			lea 	eax,szParentPath
		.else
			.break
		.endif
	.endw

	; ------- seh trapper ------- ;
	SehTrap 	__aftfz
		ErrorDump 	"AddFileToTrustZone",offset AddFileToTrustZone,offset szTrustzoneasm
	SehEnd 		__aftfz
	
	ret

AddFileToTrustZone endp

align 16

RemoveFileFromTrustZone proc uses edi esi ebx fname:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__rfftz
	
	mov edi,TrustDatabase
	.if !edi
		SehPop 	
		return_0
	.endif
	
	mov 	ebx,TrustDatabaseSize
	sub 	ebx,sizeof TRUSTFILE
	.if 	ebx == 4
		mov 	esi,offset szTrustDataFile
		invoke 	SetFileAttributes,esi,FILE_ATTRIBUTE_NORMAL
		.if 	eax!=-1
			invoke 	DeleteFile,esi
		.endif
		call 	UnLoadTrustDatabase
		SehPop
		ret
	.endif
	
	valloc 	ebx
	.if 	!eax
		ViewError	hTrustZoneWnd,"Cannot allocate memory for update trust zone database."
		SehPop
		return_0
	.endif
	mov 	esi,eax
	push 	esi
	.while byte ptr [edi]
		invoke 	lstrcmpi,fname,edi
		.if 	!zero?
			invoke 	MyCopyMem,esi,edi,sizeof TRUSTFILE
			add 	esi,sizeof TRUSTFILE
		.endif
		add 	edi,sizeof TRUSTFILE
	.endw
	call 	UnLoadTrustDatabase
	pop 	TrustDatabase
	mov 	TrustDatabaseSize,ebx
	
	mov 	esi,offset szTrustDataFile
	invoke 	SetCurrentDirectory,offset szMyDir
	
	invoke 	SetFileAttributes,esi,FILE_ATTRIBUTE_NORMAL
	.if 	eax!=-1
		invoke 	DeleteFile,esi
	.endif
	
	invoke 	CreateFile,esi,GENERIC_WRITE,FILE_SHARE_WRITE,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0
	.if 	eax && eax != -1 
		mov 	edi,eax
		sub 	ebx,4
		invoke 	WriteFile,edi,TrustDatabase,ebx,ADDR brw,0
		.if 	!eax
			ViewError	hTrustZoneWnd,"Cannot update trust database file. write error."
		.endif
		invoke 	CloseHandle,edi
	.endif
	
	; ------- seh trapper ------- ;
	SehTrap 	__rfftz
		ErrorDump 	"RemoveFileFromTrustZone",offset RemoveFileFromTrustZone,offset szTrustzoneasm
	SehEnd 		__rfftz
	
	ret

RemoveFileFromTrustZone endp

align 16

ClearTrustZone proc uses esi
	
	invoke 	MessageBox,hTrustZoneWnd, \
			reparg("Are you sure to remove all trusted file from Trust Zone?"), \
			offset szAppName,MB_OKCANCEL or MB_ICONQUESTION
	.if 	eax==IDOK
		
		mov 	esi,offset szTrustDataFile
		invoke 	SetCurrentDirectory,offset szMyDir
		invoke 	SetFileAttributes, \
				esi, \
				FILE_ATTRIBUTE_NORMAL
		.if 	eax!=-1
			invoke 	DeleteFile,esi
			.if 	!eax
				ViewError	hTrustZoneWnd, \
				"Cannot delete trustzone.dat file, please delete it manualy."
			.else
				call 	UnLoadTrustDatabase
			.endif
		.endif
	.endif
	
	ret

ClearTrustZone endp

align 16

SetTrustZoneState proc

	LOCAL 	tmp:DWORD
	mov 	tmp,0
	.if 	TrustDatabase
		mov 	tmp,1
	.endif
	push 	esi
	push 	edi
	
	mov 	esi,GetDlgItem
	mov 	edi,EnableWindow
	
	scall 	esi,hTrustZoneWnd,1006	; <-- CLEAR BTN ;
	scall 	edi,eax,tmp
	scall 	esi,hTrustZoneWnd,1005	; <-- REMOVE ;
	scall 	edi,eax,tmp
	
	pop 	edi
	pop 	esi
	
	ret

SetTrustZoneState endp

align 16

TrustZoneDlgProc proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	
	mov 	eax,uMsg
	.if 	eax==WM_INITDIALOG
		mov2	hTrustZoneWnd,hWin
		
		.if 	TimeForBlind
			mov 	eax,offset szAppName
		.else
			mov 	eax,reparg("Trust Zone")
		.endif
		invoke 	SetWindowText,hWin,eax
		
		invoke 	SetDlgItemText,hWin,1002,offset szTrusZoneDescription
		
		call 	RenewTrustListItem
		call 	SetTrustZoneState
		
		invoke 	ShowWindow,hWin,SW_SHOW
		invoke 	UpdateWindow,hWin
		invoke 	SetFocus,hWin
	.elseif 	eax==WM_COMMAND
		mov 	eax,wParam
		and 	eax,0FFFFh
		.if 	eax == 1004 	; <-- CLOSE ;
			jmp 	@close
		.elseif 	eax == 1003 	; <-- ADD FILE ;
			
			call	AddFileToTrustZone
			
		.elseif 	eax == 1005		; <-- REMOVE ;
			push esi
			
			analloc 	MAX_PATH
			.if eax
				mov esi,eax
				
				invoke 	GetDlgItem,hWin,1001
				push 	eax
				invoke 	SendMessage,eax,LB_GETCURSEL,0,0
				mov 	ecx,eax
				pop 	eax
				cmp 	ecx,-1
				.if 	zero?
					invoke 	MessageBox,hWin, \
							reparg("Please select object first."), \
							offset szAppName,MB_OK
					jmp 	_skip
				.endif
				invoke 	SendMessage,eax,LB_GETTEXT,ecx,esi
				.if byte ptr [esi]
					invoke 	RemoveFileFromTrustZone,esi
				.endif
				call 	RenewTrustListItem
				
			_skip:
				anfree esi
			.else 
				ViewError	hWin,offset szMemAllocError
			.endif
			pop esi
			
		.elseif 	eax==1006	; <-- CLEAR ;
			call 	ClearTrustZone
			call 	RenewTrustListItem
		.endif
	.elseif 	eax == WM_CLOSE
@close:
		invoke 	EndDialog,hWin,0
	.endif
	
	xor 	eax,eax
	ret

TrustZoneDlgProc endp

align 16

StartTrustZone proc

	invoke 	DialogBoxParam,hInstance,IDD_TRUSTZONE,hMainWnd,offset TrustZoneDlgProc,0
	
	ret

StartTrustZone endp

align 16

DoSignAsTrust proc uses esi edi
	
	LOCAL 	lvi:LV_ITEM
	LOCAL 	lbuff[MAX_PATH+1]:BYTE
	
	invoke 	MessageBox,hMainWnd, \
			reparg("Do you want to add this file to trust zone?"), \
			offset szAppName,MB_ICONQUESTION or MB_OKCANCEL
	.if 	eax!=IDOK
		return_0
	.endif
	
	lea 	esi,lvi
	invoke 	MyZeroMemory,esi,sizeof LV_ITEM
	lea 	edi,lbuff
	invoke 	MyZeroMemory,edi,MAX_PATH
	
	
	invoke 	SendMessage,hMainList,LVM_GETNEXTITEM,-1,LVNI_SELECTED
	.if 	eax!=-1
		
		mov 	[lvi.imask],LVIF_TEXT
		mov 	[lvi.iItem],eax
		mov 	[lvi.iSubItem],1
		mov 	[lvi.pszText],edi
		mov 	[lvi.cchTextMax],256
		invoke 	SendMessage,hMainList,LVM_GETITEM,0,esi
		.if 	byte ptr [edi]
			invoke 	AddFileToTrustDBraw,edi,1
			invoke 	SendMessage,hMainList,LVM_DELETEITEM,[lvi.iItem],0
		.endif
		
	.endif
	
	ret

DoSignAsTrust endp
