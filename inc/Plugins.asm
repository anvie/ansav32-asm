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

; ------- Plugins.asm ------- ;

APF_RESTART 	equ 9000
APF_EXIT 		equ 9001
APF_SETREG_HKLM		equ 9002
APF_SETREG_HKCU		equ 9003


APF_GETMODFNAME		equ 9005
APF_GETMYDIR		equ 9006

APF_GETVERSION		equ 9007
APF_ISCOMPATIBLE	equ 9008

.data?


	ANSAVFUNCIO struct 
		SetCtrlDS 			dd ?
		SetActionTbState	dd ?
		SetMainTxtStatus	dd ?
		AppendLogConsole	dd ?
		AnsavAbout			dd ?
		InScanning			dd ?
		InAction			dd ?
		APFunction			dd ?
	ANSAVFUNCIO ends

	PLUGINSINFO struct
		hInstance		dd ?
		hMainWnd		dd ?
		hMainList		dd ?
		hMainMenu		dd ?
		hMainPopMenu 	dd ?
		hPluginsMenu	dd ?
		ttBlind			dd ?
		lpsAppName		dd ?
		AnsavFuncIO		ANSAVFUNCIO <>
	PLUGINSINFO ends

	PluginsBuffer		dd ?
	PluginsBufferSize	dd ?
	PluginsBufferState	dd ?

	LastLoadedPlugin	dd ?

	PluginsTables		dd 100 dup(?)
	
	PluginsCount		dd ?
	
	PLUGINSIOCTL struct
		hModule				dd ?
		AnsavPluginsInit	dd ?
		AnsavPluginStart	dd ?
		CtrlDSEvent			dd ?
		CheckFileEvent		dd ?
		ExPluginsName		dd ?
		MenuID				dd ?
	PLUGINSIOCTL ends
	
.data
	PluginsTableState		dd offset PluginsTables
	
	DynPluginsMenu			dd 20000
	DynPluginsMenuMin		dd 20000
	DynPluginsMenuMax		dd 30000
.code


align 16

_InScanning	proc
	mov 	eax,InScanning
	ret
_InScanning endp

align 16

_InAction proc
	mov 	eax,InAction
	ret
_InAction endp

align 16


ProcessPlugins proc uses edi esi ebx	MenuID:DWORD

	; ------- seh installtion ------- ;
	SehBegin 	__pp

	lea 	esi,PluginsTables
	
	invoke 	AppendLogConsole, \
			reparg("Starting plugin...")
@lp:
	lodsd	
	test 	eax,eax
	jnz 		@F
		invoke 	AppendLogConsole, \
				reparg("Cannot start plugin, initialization NULL")
		jmp 	@endl
	@@:
		mov 	ebx,eax
		mov 	eax,MenuID
		cmp 	[ebx.PLUGINSIOCTL].MenuID,eax
		jne 	@nx
			.if 	[ebx.PLUGINSIOCTL].AnsavPluginStart
				msign esi
				call 	[ebx.PLUGINSIOCTL].AnsavPluginStart
				invoke 	AppendLogConsole, \
						reparg("Plugin loaded...")
			.else
				invoke 	AppendLogConsole, \
						reparg("Cannot start plugin, may corrupted.")
			.endif
			jmp 	@endl
		@nx:
	jmp 	@lp
	
@endl:

	; ------- seh trapper ------- ;
	SehTrap 	__pp
		ErrorDump	"ProcessPlugins",offset ProcessPlugins,"Plugins.asm"
	SehEnd		__pp

	ret

ProcessPlugins endp

align 16

CheckForValidPlugins proc uses esi ebx edi lpFile:DWORD, PluginsIOCtl:DWORD
	
	LOCAL 	pd:PLUGINSINFO
	LOCAL 	retv:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__cfvp
	
	mov 	retv,0
	
	analloc	MAX_PATH+1
	mov 	esi,eax
		
		invoke 	GetModuleHandle,lpFile
		test 	eax,eax
		jnz 	@getplg
		
		; ------- check for valid PE ------- ;
		invoke 	IsThisFilePEValid,lpFile
		test 	eax,eax
		jz 		@nx
		
		invoke 	LoadLibrary,lpFile
		.if 	eax
@getplg:
			mov 	ebx,eax
			mov 	LastLoadedPlugin,ebx
			mov 	edi,PluginsIOCtl
			
			invoke 	GetProcAddress,ebx,reparg("AnsavPluginsInit")
			.if 	eax
				
				mov 	edx,dword ptr [edi]
				mov 	[edx.PLUGINSIOCTL].hModule,ebx
				mov 	[edx.PLUGINSIOCTL].AnsavPluginsInit,eax	; <-- fill 1 ;
				
				mov 	ecx,eax
				m2m 	[pd.hInstance],hInstance
				m2m 	[pd.hMainWnd],hMainWnd
				m2m 	[pd.hMainList],hMainList
				m2m		[pd.hMainMenu],hMainMenu
				m2m 	[pd.hMainPopMenu],hMainPopMenu
				m2m 	[pd.hPluginsMenu],hToolsPopMenu
				mov 	eax,TimeForBlind
				mov 	[pd.ttBlind],eax
				lea 	eax,szAppName
				mov 	[pd.lpsAppName],eax
				
				; ------- function ShowAnsavAboutDialog ------- ;
				lea		eax,ShowAboutDialog
				mov 	[pd.AnsavFuncIO.AnsavAbout],eax
				
				; ------- function to Log console ------- ;
				lea 	eax,AppendLogConsole
				mov 	[pd.AnsavFuncIO.AppendLogConsole],eax
				
				; ------- function to Set main txt status ------- ;
				lea 	eax,SetMainTxtStatus
				mov 	[pd.AnsavFuncIO.SetMainTxtStatus],eax
				
				; ------- function ac/de activate TB action state ------- ;
				lea 	eax,SetActionTbState
				mov 	[pd.AnsavFuncIO.SetActionTbState],eax
				
				; ------- function ac/de Control2/menu durring scanning ------- ;
				lea 	eax,SetCtrlDS
				mov 	[pd.AnsavFuncIO.SetCtrlDS],eax
				
				; ------- InScanning ------- ;
				lea 	eax,_InScanning
				mov 	[pd.AnsavFuncIO.InScanning],eax
				
				; ------- InAction ------- ;
				lea 	eax,_InAction
				mov 	[pd.AnsavFuncIO.InAction],eax
				
				; ------- APFunction ------- ;
				lea 	eax,AnsavPluginsFuncProc
				mov 	[pd.AnsavFuncIO.APFunction],eax
				
				lea 	eax,pd
				push 	eax
				call 	ecx	; <-- PLUGIN INIT ;
				add 	esp,4
				.if 	!eax
					; ------- not campatible ------- ;
					invoke 	FreeLibrary,ebx
					jmp 	@nx
				.endif
			.endif
			invoke 	GetProcAddress,ebx,reparg("ExPluginName")
			.if 	eax
				mov 	edx,dword ptr [edi]
				mov 	[edx.PLUGINSIOCTL].ExPluginsName ,eax	; <-- fill 2;
				
				call 	eax
				mov 	retv,eax
			.endif
			invoke 	GetProcAddress,ebx,reparg("AnsavPluginStart")
			.if 	eax
				mov 	edx,dword ptr [edi]
				mov 	[edx.PLUGINSIOCTL].AnsavPluginStart ,eax	; <-- fill 3 ;
			.endif
			invoke 	GetProcAddress,ebx,reparg("CtrlDSEvent")
			.if 	eax
				mov 	edx,dword ptr [edi]
				mov 	[edx.PLUGINSIOCTL].CtrlDSEvent ,eax	; <-- fill 4 ;
			.endif
			invoke 	GetProcAddress,ebx,reparg("CheckFileEvent")
			.if 	eax
				mov 	edx,dword ptr [edi]
				mov 	[edx.PLUGINSIOCTL].CheckFileEvent ,eax	; <-- fill 5 ;
			.endif
		.endif
@nx:
	anfree	esi
	
	; ------- seh trap ------- ;
	SehTrap 	__cfvp
		ErrorDump 	"CheckForValidPlugins",offset CheckForValidPlugins,"Plugins.asm"
	SehEnd		__cfvp
	
	mov 	eax,retv
	ret

CheckForValidPlugins endp

align 16

InsertPlugins proc uses edi esi lpPluginsName:DWORD
	
	LOCAL 	mi:MENUITEMINFO
	LOCAL 	NewBufferSize:DWORD
	LOCAL 	retv:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__ip
	
	invoke 	MyZeroMemory,ADDR mi,sizeof MENUITEMINFO
	mov 	retv,0
	
	; ------- MAKE EXTRA MENU ------- ;
	mov 	[mi.cbSize],sizeof MENUITEMINFO
	mov 	[mi.fMask],MIIM_DATA OR MIIM_ID OR MIIM_STATE OR MIIM_SUBMENU OR MIIM_TYPE
	
	.if 	!hToolsPopMenu
		invoke CreatePopupMenu
		mov 	hToolsPopMenu,eax
		mov 	[mi.fType],MFT_STRING
		mov 	[mi.wID],IDM_TOOLS
		m2m 	[mi.hSubMenu],hToolsPopMenu
		mov 	[mi.dwTypeData],reparg("Plugins")
		invoke 	InsertMenuItem,hMainMenu,3,1,ADDR mi
		invoke 	DrawMenuBar,hMainWnd
	.endif
	
	; ------- create buffer ------- ;
	.if 	!PluginsBuffer
		valloc 	2
		.if 	eax
			mov 	PluginsBuffer,eax
			mov 	PluginsBufferState,eax
			mov 	PluginsBufferSize,1
			mov 	byte ptr [eax],'P'
		.endif
	.endif
	
	cmp 	PluginsBuffer,0
	jne 	@F
		invoke 	AppendLogConsole,reparg("Cannot allocate memory for Plugins buffer str")
		SehPop
		xor 	eax,eax
		ret
	@@:
	
	; ------- check for existing plugins ------- ;
	mov 	edi,PluginsBuffer
	@lp:
		
		invoke 	lstrcmpi,edi,lpPluginsName
		.if 	zero?
			; ------- unload plugins and out ------- ;
			.if 	LastLoadedPlugin
				invoke 	FreeLibrary,LastLoadedPlugin
			.endif
			SehPop
			xor 	eax,eax
			ret
		.endif
		
	NextArray 	@lp

	mov 	PluginsBufferState,edi

	; check plugins length name
	strlen lpPluginsName
	
	mov 	ecx,edi
	add 	ecx,eax
	mov 	edx,PluginsBuffer
	add 	edx,PluginsBufferSize
	cmp 	ecx,edx
	jb		@F
		; ------- renew buffer size ------- ;
		sub 	ecx,edi
		inc 	ecx
		mov 	NewBufferSize,ecx
		valloc 	ecx
		.if 	eax
			mov 	esi,eax
			
			; copy data from old buffer
			invoke 	MyCopyMem,esi,PluginsBuffer,PluginsBufferSize
			
			; free old buffer
			vfree 	PluginsBuffer
			
			; renew handle
			mov 	eax,esi
			add 	eax,PluginsBufferSize
			inc 	eax
			mov 	PluginsBufferState,eax
			mov 	PluginsBuffer,esi
			mov 	eax,NewBufferSize
			add 	PluginsBufferSize,eax
		.endif
	@@:
	
	; ------- write Plugin name to buffer ------- ;
	invoke 	lstrcpy,PluginsBufferState,lpPluginsName
	
	; renew handle
	strlen PluginsBufferState
	
	mov 	PluginsBufferState,eax

	; ------- create new sub menu ------- ;
	
	inc 	DynPluginsMenu
	mov 	eax,DynPluginsMenu
	mov 	[mi.wID],eax
	
	mov 	edx,PluginsTableState
	sub 	edx,4
	mov 	edx,[edx]
	mov 	[edx.PLUGINSIOCTL].MenuID,eax	; <-- fill 6 ;  
	
	mov 	[mi.hSubMenu],0
	m2m 	[mi.dwTypeData],lpPluginsName
	invoke 	InsertMenuItem,hToolsPopMenu,0,TRUE,ADDR mi
	
	mov 	retv,eax
	
	; ------- seh trap ------- ;
	SehTrap 	__ip
		ErrorDump	"InsertPlugins",offset InsertPlugins,"Plugins.asm"
	SehEnd		__ip
	
	mov 	eax,retv
	ret 

InsertPlugins endp

align 16

SearchPlugins proc uses edi lpPath:DWORD

	LOCAL 	hFind:DWORD
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	LOCAL 	wfd:WIN32_FIND_DATA
	LOCAL 	len:DWORD
	
	; ------- seh installation ------- ;
	SehBegin	__sp
	
IFDEF	RELEASE
	; ------- don't load plugins if run in reverser environment ------- ;
	push 	esi
		mov 	esi,hInstance
		add 	esi,03ch
		add 	si,[esi]
		sub 	si,03ch
		cmp 	[esi.IMAGE_NT_HEADERS].FileHeader.NumberOfSections,2
		je 		@F
			add 	esp,4h
			SehPop
			ret
		@@:
	pop		esi
ENDIF
	
	lea 	edi,lBuff
	
	invoke 	MyZeroMemory,ADDR wfd,sizeof WIN32_FIND_DATA
	invoke 	MyZeroMemory,edi,MAX_PATH
	
	invoke 	lstrcpy,edi,lpPath
	
	invoke 	TruePath,edi
	
	strlen edi
	
	mov 	len,eax
	mov 	byte ptr [edi+eax],'*'
	
	
	invoke	FindFirstFile,edi,ADDR wfd
	.if 	eax!=-1 && eax!=0
		mov 	hFind,eax
		.while 	eax
			mov		eax,[wfd.dwFileAttributes] 
			.if 	!(ax & FILE_ATTRIBUTE_DIRECTORY)
				
				mov 	eax,len
				mov 	byte ptr [edi+eax],0
				lea 	eax,[wfd.cFileName]
				invoke 	lstrcat,edi,eax
				
				; ------- alloc mem for new plugins ------- ;
				valloc 	sizeof 	PLUGINSIOCTL
				.if 	!eax
					invoke 	AppendLogConsole,reparg("Cannot allocate memory for new plugins")
					SehPop
					ret
				.endif
				mov 	edx,PluginsTableState
				mov 	dword ptr [edx],eax
				add 	PluginsTableState,4	; <-- renew state ;
				
				invoke 	CheckForValidPlugins,edi,edx	; <-- check & fill buffer ;
				.if 	eax
					invoke 	InsertPlugins,eax
					test 	eax,eax
					jz 		@undo
						inc 	PluginsCount
				.else
				@undo:
					; ------- undo changes ------- ;
					sub 	PluginsTableState,4
					mov 	eax,PluginsTableState
					push 	eax
					vfree 	[eax]
					pop 	eax
					mov 	dword ptr [eax],0
					;dec 	PluginsCount
				.endif
			.endif
			
			invoke 	FindNextFile,hFind,ADDR wfd
		.endw
		
		invoke 	FindClose,hFind
	.endif

	; ------- Seh trapper ------- ;
	SehTrap 	__sp
		ErrorDump 	"SearchPlugins",offset SearchPlugins,"Plugins.asm"
	SehEnd		__sp

    ret

SearchPlugins endp


align 16

InitPlugins proc uses edi esi ebx ecx edx
	
	; ------- check path ------- ;
	invoke 	SearchPlugins,ADDR szPluginsPath
	
	ret

InitPlugins endp

align 16

CleanupPlugins proc uses esi 
	
	; ------- seh installation ------- ;
	SehBegin 	_cp
	
	lea 	esi,PluginsTables
	mov 	ecx,PluginsCount
	
	test 	ecx,ecx
	jz 		@endl
	js 		@endl
	
	@lp:
	push 	ecx
	lodsd
		test 	eax,eax
		.if 	!zero?
			
			vfree 	eax	; <-- clean up memory ;
			mov 	dword ptr [esi-4h],0
			
		.endif
	pop 	ecx
	loop 	@lp

@endl:
	; ------- seh trapper ------- ;
	SehTrap 	_cp
		ErrorDump 	"CleanupPlugins",offset CleanupPlugins,reparg("plugins.asm")
	SehEnd 		_cp
	
	ret

CleanupPlugins endp

align 16

AnsavPluginsFuncProc proc ua:DWORD,ub:DWORD,uc:DWORD,ud:DWORD

	LOCAL 	retv:DWORD
	
	mov 	retv,1
	
	mov 	eax,ua
	.if 	eax==APF_RESTART
		
		call 	DoReboot
		;ViewError	hMainWnd,reparg("call 	DoReboot")
		jmp 	GlobalExit
		
	.elseif 	eax==APF_EXIT
		
		jmp 	GlobalExit
		
	.elseif 	eax==APF_SETREG_HKLM
		
		;ViewError	0,"invoke 	SetRegString,HKEY_LOCAL_MACHINE,ub,uc,ud"
		invoke 	SetRegString,HKEY_LOCAL_MACHINE,ub,uc,ud
		
	.elseif 	eax==APF_GETMODFNAME
		
		mov 	retv,offset szMyPath
		
	.elseif 	eax==APF_GETMYDIR
	
		mov 	retv,offset szMyDir
		
	.elseif 	eax==APF_GETVERSION
		
		
	.elseif 	eax==APF_ISCOMPATIBLE
		
		mov 	retv,1
		mov 	eax,ub
		mov 	ecx,uc
		mov 	edx,ud
		cmp 	eax,VerMajor
		jb 		@F
		cmp 	ecx,VerMinor
		jb 		@F
		cmp 	edx,VerRevision
		jb 		@F
			mov 	retv,0
		@@:
		
	.endif
	
	
	mov 	eax,retv
	ret
AnsavPluginsFuncProc endp

align 16






