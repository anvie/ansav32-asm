;
;
;
;      Ansav Advanced Source Code
;      By: [4NV|e] C: anvie@ansav.com
;
;      http://www.ansav.com
;
;
;
;
;=================================================================;

; ------- Ansav.asm ------- ;
; Main file 
.586
;.MMX
.XMM
.model 	flat, stdcall
option 	casemap:none

; ------- Main Include ------- ;
include Ansav.inc


.code	; ------- Code Start ------- ;

Align 16

; ------- Ansav Initial ------- ;
AnsavInitFirst proc uses edi esi ebx
	
	
IFDEF 	DEBUG
	; ------- Init for debug ------- ;
	mov 	hFileLog,0
	call 	InitLog
ENDIF
IFDEF 	ERRORLOG
	mov 	hFileErrorLog,0
	mov 	ErrorOccured,0
ENDIF

	mLog	"AnsavInitFirst::"
	
	xor 	eax,eax
	mov 	incmdl,eax
	mov 	NoStealth,eax
	mov 	HaveMMX,eax
	mov 	PluginsCount,eax
	mov 	SomeObjectNeedReboot,eax
	mov 	CmdLineScan,eax
	
	; ------- Init for ansav needed value ------- ;
	push 	0
	call 	GetModuleHandle
	mov    	hInstance,eax
	call 	GetCommandLine
	mov		CommandLine,eax
	call 	InitCommonControls
	
	; ------- determine processor is support MMX ? ------- ;
	inc	 	eax
	cpuid
	test 	edx,200000h
	jz 		@F
		mov 	HaveMMX,1
	@@:
	
	invoke 	MyZeroMemory,ADDR icex,sizeof INITCOMMONCONTROLSEX
	mov 	[icex.dwSize],sizeof INITCOMMONCONTROLSEX	; <-- compability ;
	mov 	[icex.dwICC],ICC_COOL_CLASSES
	
	mLog	"Loading comctl32.dll::"
	
	invoke 	LoadLibrary,reparg("comctl32.dll")
	.if 	eax
		invoke 	GetProcAddress,eax,reparg("InitCommonControlsEx")
		.if 	eax
			mLog	"[ok]"
			lea 	edx,icex
			push 	edx
			call 	eax
IFDEF 	DEBUG
		.else
			mLog	"[failed]"
ENDIF
		.endif
IFDEF 	DEBUG
	.else
		mLog "[failed]"
ENDIF
	.endif
	
	; ------- Check for NT Window$ Version ------- ;
	mLog 	"Check for Windows Version"
	invoke 	IsNT
	.if 	eax
		mLog 	"..Windows is NT/2K/XP"
		mov 	WinVerNT,1
	.else
		mLog 	"..Windows not NT/2K/XP"
		mov 	WinVerNT,0
	.endif

	; ------- Escalate privileges ------- ;
	call 	SetToken
	
	; ------- keep run one instance ------- ;
	call 	IsAnsavRun?
	.if 	eax
		invoke 	MessageBox,0, \
				reparg("ANSAV already running..."), \
				offset szAppName,MB_OK
		invoke 	ExitProcess,0
	.endif
	
	; ------- Buffering, get MyDir, MyPath etc... ------- ;
	call 	GetPathPath
	
	
	; ------- LOAD CONFIGURATION ------- ;
	push 	1
	call 	LoadConfig
	
	xor 	eax,eax
	
	; ------- set null flag ------- ;
	mov 	pBufferVirusInfo,eax
	mov 	BufferVirusInfoSize,eax
	
	; ------- init buffer for last scanned path ------- ;
	mov 	LastScannedPath,eax
	mov 	LastScannedPathSize,eax
	mov 	ArcReady,eax

	; ------- componen ------- ;
	call 	LoadComponen
	
	; ------- time for blind sucker ------- ;
	call 	BlindSucker
	
AnsavInitFirstSize equ $ - offset AnsavInitFirst
	
	; ------- build CRC 32 table ------- ;
	call 	crcInit
	
	; ------- VERTICAL LOGO ------- ;
	invoke 	LoadBitmap,hInstance,IMG_VLOGO
	mov 	hVLogoBmp,eax
	
	; ------- decrypt vbd ------- ;
IFDEF 	RELEASE
	call 	DecryptVDB
ENDIF

	call 	IsAlreadyInstalled?
	mov 	AlreadyInstalled,eax
	.if 	!eax
		.if 	!TimeForBlind
			invoke 	lstrcat,ADDR szAppName,reparg(" - [ PORTABLE ]")
		.endif
	.endif

	invoke 	LoadIcon,hInstance,IDI_MAIN_ICON
	mov 	hMainIcon,eax


	; ------- check for external database ------- ;
	xor 	eax,eax
	mov 	ExternalVdb,eax
	mov 	ExternalVdbSize,eax
	call 	LoadExVdb
	
	call 	RenewConfigFlags

	; ------- check exvdb ver compare ------- ;
	.if		ExternalVdb && ExternalVdbSize
		mov 	esi,ExternalVdb
		movzx 	eax,[esi.EXVDBINFO].wDay
		movzx 	ecx,[esi.EXVDBINFO].wMonth
		movzx 	edx,[esi.EXVDBINFO].wYear
		
		cmp 	edx,dwRDYear
		ja		@F
		cmp 	ecx,dwRDMonth
		ja 		@F
		cmp		eax,dwRDDay
		ja 		@F
			jmp 	@nver
		@@:
		
		mov 	dwRDYear,edx
		mov 	dwRDMonth,ecx
		mov 	dwRDDay,eax
	.endif
@nver:

	; ------- immune registry ------- ;
	call 	RegImmune
	
	; get explorer PID, exclude from heuristic engine 
	invoke 	FindWindow,0,reparg("Start Menu")
	.if 	eax
		invoke 	GetWindowThreadProcessId,eax,offset ExplorerPID
	.endif

	; ------- load trusted database ------- ;
	call 	LoadTrustDatabase

	call 	OnLatestUpdate
	
	; ------- check oldiest engine alias kadaluwarsa! ------- ;
	call	IsOldiest?
	
	; ------- check etc host file ------- ;
	call 	CheckEtcHost

	; ------- set antidump ------- ;
	call 	AntiDump
	ret

AnsavInitFirst endp

Align 16
WndProc PROTO :HWND,:UINT,:WPARAM,:LPARAM

; ------- Win Main procedure ------- ;
WinMain proc hInst:HINSTANCE,hPrevInst:HINSTANCE,CmdLine:LPSTR,CmdShow:DWORD
	LOCAL	wc:WNDCLASSEX
	LOCAL	msg:MSG

	mLog 	"WinMain enter::"
	
	invoke 	MyZeroMemory,ADDR wc,sizeof WNDCLASSEX
	
	mov		[wc.cbSize],sizeof WNDCLASSEX
	mov		[wc.style],CS_HREDRAW or CS_VREDRAW
	mov		[wc.lpfnWndProc],offset WndProc
	mov		[wc.cbClsExtra],NULL
	mov		[wc.cbWndExtra],DLGWINDOWEXTRA
	push	hInst
	pop		[wc.hInstance]
	mov		[wc.hbrBackground],COLOR_BTNFACE+1
	mov		[wc.lpszMenuName],IDM_MAIN_MENU
	mov		[wc.lpszClassName],offset szClassName
	mov 	eax,hMainIcon
	mov		[wc.hIcon],eax
	mov		[wc.hIconSm],eax
	invoke LoadCursor,NULL,IDC_ARROW
	mov		wc.hCursor,eax

	invoke RegisterClassEx,addr wc
	
	mErrorTrap eax,"cannot register class",@endl
	
	mLog 	"CreateDialogParam..."
	invoke CreateDialogParam,hInstance,IDD_DIALOG,NULL,offset WndProc,NULL
	mov 	hMainWnd,eax
	
	mErrorTrap	eax,"cannot Create main window",@endl
	
	invoke UpdateWindow,hMainWnd
	invoke 	SetLastError,0
	
	invoke 	MyZeroMemory,ADDR msg,sizeof MSG
	
	invoke 	Sleep,100
	
	.while TRUE
		invoke 	IsWindow,hMainWnd
		test 	eax,eax
		jz 		@endl
		
		invoke GetMessage,addr msg,NULL,0,0
	  .BREAK .if !eax
		invoke TranslateMessage,addr msg
		invoke DispatchMessage,addr msg
	.endw
	mov		eax,[msg.wParam]
	ret
@endl:
	xor 	eax,eax
	ret
WinMain endp

align 16

; ------- Main Window Procedure ------- ;
WndProc proc hWin:HWND,uMsg:UINT,wParam:WPARAM,lParam:LPARAM
	LOCAL 	ps,hDC,hOld,memDC:DWORD

	mov		eax,uMsg
	.if eax==WM_INITDIALOG  	; ------- Initial dialog ------- ;
		push	hWin
		pop		hMainWnd
		
		.if 	!TimeForBlind
			invoke 	SetWindowText,hWin,ADDR szAppName
		.else
			invoke 	SetWindowText,hWin,ADDR szRandomString
		.endif
		
		push 	ebx
		push 	esi
		
		mov 	ebx,GetDlgItem
		mov 	esi,hMainWnd
		
		scall 	ebx,esi,IDC_MAIN_PB
		mov 	hMainProgBar,eax
		scall 	ebx,esi,IDC_EDIT_PATH
		mov 	hMainEditPath,eax
		scall 	ebx,esi,IDC_TXT_STATUS
		mov		hMainTxtStatus,eax 	
		scall 	ebx,esi,IDC_TXT_CHKFILES
		mov 	hTxtCheckedFiles,eax
		scall 	ebx,esi,IDC_TXT_THREATDETC
		mov 	hTxtDetectedThreats,eax
		scall 	ebx,esi,IDC_TXT_PERCENT
		mov 	hTxtMainPercent,eax
		
		pop 	esi
		pop 	ebx
		
		invoke 	GetMenu,hWin
		mov 	hMainMenu,eax
		
		; ------- Build-build ------- ;
		call 	BuildMainListview
		call 	BuildMainTxtStatus
		call 	BuildToolbar
		call 	BuildMainMenuPic
		call 	BuildMainPopMenu
		
		call 	SetAllMainCtrlState
		invoke 	SendMessage,hToolBar, \
				TB_ENABLEBUTTON,IDC_MAINTB_STOP,STATE_DISABLE
		
		; ------- Create timer to monitor existing rem media ------- ;
		call 	SetMainTimer
		
		; ------- Check for existing threat in mem ------- ;
		mov 	MemCheck,1
		call 	CheckAndProcessBVI
		.if 	eax
			invoke 	SetMainTxtStatus,STATUS_DETECTED
			invoke 	SetActionTbState,STATE_ENABLE
		.else
			invoke 	SetMainTxtStatus,STATUS_CLEAN
			invoke 	SetActionTbState,STATE_DISABLE
		.endif
		mov 	MemCheck,0
		
		; ------- Set status ------- ;
		StatusIdleWait
		; make status clr show ttl
		call 	SetStatusClrTtl
		
		.if 	!NoPlugins
			call 	BuildPlugins
		.endif
		
		; ------- create syncro hook ------- ;
		
		.if 	ShowLog
			call 	ShowLogWindow
		.endif
		
		invoke 	VerticalTile,hWin,IMG_VREDTILE,70
		
		; ------- is already installed? ------- ;
		call 	CheckInstalled
		
		.if 	StealthMode && hStealthmMap
			mov 	eax,hStealthmMap
			m2m 	[eax.CEST].hMainWnd,hWin
			m2m 	[eax.CEST].hWnd2,hWin
		.endif
		
		invoke 	SetTimer,hWin,2194,2000,offset MakeUnkillable
		
		call 	SetMenuInstallable
		
		
		; ------- auto check update ------- ;
		mov 	hAutUpdCheckThread,0
		lea 	eax,AutomaticUpdateCheck
		invoke 	CreateThread,0,0,eax,0,0,offset brw
		mov 	hAutUpdCheckThread,eax
		
		call 	DontHookme
		
		invoke 	SetForegroundWindow,hWin
		invoke 	SetFocus,hWin
		
		.if 	CmdLineScan
			invoke 	StartScanOnlyDir,CmdLineScan
		.endif
		
	.elseif 	eax == WM_PAINT
		invoke LocalAlloc,LPTR,sizeof PAINTSTRUCT
		mov 	ps,eax
		
		invoke  BeginPaint,hWin,ps
		mov     hDC, eax
		
		invoke  CreateCompatibleDC,hDC
		mov     memDC, eax
		
		invoke  SelectObject,memDC,hVLogoBmp
		mov     hOld, eax
		
		invoke  BitBlt,hDC,1,1,80,400,memDC,0,0,SRCCOPY
		
		invoke  SelectObject,hDC,hOld
		invoke  DeleteDC,memDC
		
		invoke  EndPaint,hWin,ps
		invoke  ReleaseDC,hWin,hDC
		
		invoke 	LocalFree,ps
	.elseif 	eax == WM_COMMAND		; ------- Command Control ------- ;
		mov		eax,wParam
		and		eax,0FFFFh
		
		; ------- Menu-Menu ------- ;						; --------------------[ -= MENU =- ]
		.if eax==IDM_FILE_EXIT
			jmp 	@close
		.elseif 	eax == IDM_FILE_SCAN
			call 	CheckAndAskIfAvailable
			.if 	eax
				call 	StartQuickScan		; <-- quick scan ;
			.endif
		.elseif 	eax == IDM_FILE_SCAN2
			call 	StartScanSingleFile				; <-- Scan single file ;
		.elseif 	eax == IDM_FILE_SCANMULTIPLEOBJECT	
			call 	CheckAndAskIfAvailable			; <-- multiple object scan ;
			.if 	eax
				call 	MultipleScanObject
			.endif
		.elseif 	eax == IDM_FILE_SCANMEM
			call 	CheckAndAskIfAvailable
			.if 	eax
				call 	QuickScanMem
			.endif
		.elseif 	eax == IDM_FILE_SCANALLREM		; <-- Scan all removable media ;
			call 	CheckAndAskIfAvailable
			.if 	eax
				call 	StartScanAllRemovableMedia
			.endif
		.elseif 	eax == IDM_FILE_SCANALLHARDISK		; <-- Scan all hardisk partition ;
			call 	CheckAndAskIfAvailable
			.if 	eax
				call 	StartScanAllHardisk
			.endif
		.elseif 	eax == IDM_FILE_SCANONLYWINDIR	; <-- scan only windows directory ;
			call 	CheckAndAskIfAvailable
			.if 	eax
				
				invoke 	StartScanOnlyDir,offset szWinDir
			.endif
		.elseif 	eax == IDM_FILE_SCANSYSDIR
			call 	CheckAndAskIfAvailable
			.if 	eax
				invoke 	StartScanOnlyDir,offset szSysDir
			.endif
		.elseif 	eax == IDM_VIEW_RESULT
			call 	ViewResult
		.elseif 	eax == IDM_VIEW_CONSOLELOG		; <-- Console style LOG ;
			call 	ShowLogWindow
		.elseif 	eax == IDM_VIEW_VDB
			invoke 	DialogBoxParam,hInstance,IDD_ANVDB,hWin,ADDR AnvdbDlgProc,0
			invoke 	ShowWindow,eax,SW_SHOW
		.elseif 	eax == IDM_VIEW_QUARZONE	; <-- view quarantine ;
			call 	ViewQuarantine
		.elseif 	eax == IDM_VIEW_TRUSTZONE
			call 	StartTrustZone
		.elseif 	eax == IDM_ADVANCED_ASHUT	; <-- Auto shutdown after scan finished ;
			.if 	!ShutdownAfterScan
				mov 	ShutdownAfterScan,1
				invoke 	CheckMenuItem,hMainMenu,IDM_ADVANCED_ASHUT,MF_CHECKED
			.else
				mov 	ShutdownAfterScan,0
				invoke 	CheckMenuItem,hMainMenu,IDM_ADVANCED_ASHUT,MF_UNCHECKED
			.endif
		.elseif 	eax == IDM_VIEW_CLEARLIST
			mov 	[LastScannedInfo.wStatus],STATUS_TAKEACTION
			invoke 	SendMessage,hMainList,LVM_DELETEALLITEMS,0,0
			invoke 	SetActionTbState,STATE_DISABLE
		.elseif 	eax == IDM_ADVANCED_CONFIG
			call 	StartConfigDlg
		.elseif 	eax == IDM_HELP_INSTALL		; <-- INSTALL ;
			call 	InstallUninstallAnsav
		.elseif 	eax==IDM_HELP_ABOUT 		; ------- About ------- ;
			push 	hWin
			call 	ShowAboutDialog
		.elseif 	eax==IDM_HELP_README
			call 	Readme
		.elseif 	eax == IDM_HELP_UPDATE	; <-- UPDATE ;
			.if 	AlreadyInstalled
				call 	Update
			.else
				invoke 	MessageBox,hWin, \
				reparg("Please install ANSAV first to use this feature"), \
				offset szAppName,MB_OK
			.endif
		
		.elseif 	eax == IDM_HELP_SUBMITTHREAT
			invoke 	ShellExecute,hWin,offset szOpen,reparg("http://ansav.com/content/view/15/34/"),0,0,SW_MAXIMIZE
		; ------- popup menu ------- ;			; --------------------[ -= POPUP MENU =- ]
		.elseif 	eax == IDM_MPM_PROPERTIES
			call 	ObjectProperties
		.elseif 	eax == IDM_MPM_GOTOOBJL
			call 	GotoObjectLocation
		.elseif 	eax == IDM_MPM_SELECTALL
			call 	SelectAllObject
		.elseif 	eax == IDM_MPM_CLEAN		; <-- clean selected object ;
			mov 	ForFix,1
			push 	1	; <-- clean only selected object ;
			call 	StartCleanNow
		.elseif 	eax == IDM_MPM_DELETE		; <-- delete selected object ;
			push 	1	; <-- clean only selected object ;
			call 	StartCleanNow
		.elseif 	eax == IDM_MPM_QUARANTINE		; <-- quarantine selected object ;
			push 	1	; <-- quarantine only selected object ;
			call 	StartQuarantineNow
		.elseif 	eax == IDM_MPM_SIGNASTRUST
			call 	DoSignAsTrust
		.elseif 	eax == IDM_MPM_COPYTHREATN
			push 	1
			call 	ClipboardCopyObject	; <-- threat name ;
		.elseif 	eax == IDM_MPM_COPYOBJPATH
			push 	2	
			call 	ClipboardCopyObject ; <-- object path ;
		
		; ------- Button-Button ------- ;			; --------------------[ -= BUTTON/TOOLBAR =- ]
		.elseif 	eax == IDC_MAINTB_EXIT
			jmp 	@close
		.elseif 	eax == IDC_MAINTB_SCAN
			call 	CheckAndAskIfAvailable
			.if 	eax
				mov 	eax,MainScanButton
				.if 	eax == 1
					call 	StartQuickScan
				.elseif 	eax == 2
					call 	ScanSingleFile
				.elseif 	eax == 3
					call 	MultipleScanObject
				.else
					call 	StartQuickScan
				.endif
			.endif
		.elseif 	eax == IDC_MAINTB_STOP
			mov 	StopScan,1
			mov 	StopClean,1
		.elseif 	eax == IDC_MAINTB_CLEAN
			; confirm
			cmp 	NoActConfirm,1
			je 		@F
			invoke 	MessageBox,hWin, \
					reparg("Are you sure to clean all detected object?"), \
					ADDR szAppName,MB_ICONQUESTION or MB_OKCANCEL
			.if 	eax == IDOK
				@@:
				mov 	ForFix,1
				push 	0							; <-- clean all object in list and try to clean first;
				call 	StartCleanNow
			.endif
		.elseif 	eax == IDC_MAINTB_DELETE
			; confirm
			cmp 	NoActConfirm,1
			je 		@F
			invoke 	MessageBox,hWin, \
					reparg("Are you sure to delete all detected object?"), \
					ADDR szAppName,MB_ICONQUESTION or MB_OKCANCEL
			.if 	eax == IDOK
				@@:
				push 	0							; <-- delete all object ;
				call 	StartCleanNow
			.endif
		.elseif 	eax == IDC_MAINTB_QUARANTINE
			; confirm
			cmp 	NoActConfirm,1
			je 		@F
			invoke 	MessageBox,hWin, \
					reparg("Are you sure to quarantine all detected object?"), \
					ADDR szAppName,MB_ICONQUESTION or MB_OKCANCEL
			.if 	eax == IDOK
				@@:
				push 	0							; <-- quarantine all object ;
				call 	StartQuarantineNow
			.endif
		.elseif 	eax == IDC_MAINTB_VIEWRES
			call 	ViewResult
		.endif
		
;-------------------------------------- PLUGINS ----------------------------------------;
		mov 	eax,[wParam] 
		.if	 	eax >= DynPluginsMenuMin && \
				eax <= DynPluginsMenuMax
				push 	eax
				call 	ProcessPlugins
		.endif
		
;;-------------------------------------- HOOK CODE ----------------------------------------;
;	;.elseif 	eax == WM_USER+777h
;		
;		;invoke 	ProcessThisMessage,wParam,lParam
;		;ret
;		
;;-------------------------------------- end of hook code ----------------------------------------;
	.elseif 	eax==WM_SIZE
		call 	RepositionMainWnd
	.elseif 	eax == WM_NOTIFY		; <-- notify ;
		
		push 	ebx
			mov  	ebx,lParam
			mov 	eax,[ebx.NMHDR].hwndFrom
			.if 	eax == hMainList
				.if 	[ebx.NMHDR].code == NM_RCLICK
					call 	ReleaseCapture
					call 	MainPopMenu
				.endif
			.endif
		pop 	ebx
		
	.elseif eax==WM_CLOSE			; ------- If Close ------- ;
	@close:
		; ------- confirm if scan process running ------- ;
		.if 	InScanning || InAction
			.if 	InScanning
				mov 	edx,reparg("Do you want to stop current scanning process?")
			.else
				mov 	edx,reparg("Do you want to stop current action process?")
			.endif
			invoke 	MessageBox,hWin,edx,ADDR szAppName,MB_YESNO or MB_ICONQUESTION
			 
			cmp 	eax,IDNO
			je 		@F
		.endif
		call 	MainWndCleanUp
		
		; ------- check uncleanable object ------- ;
		.if 	SomeObjectNeedReboot
			invoke 	wsprintf,offset szUtilsBuff,offset szUncleanNdtrbF,SomeObjectNeedReboot
			invoke 	MessageBox,hWin,offset szUtilsBuff,offset szAppName,MB_YESNO or MB_ICONQUESTION
			.if 	eax==IDYES
				invoke 	MessageBox,hWin,offset szPleaseSave,offset szAppName,MB_OK or MB_ICONINFORMATION
				call 	DoReboot
			.endif 
		.endif
		
		invoke 	DestroyWindow,hWin
		
		jmp 	@endl
		@@:
		mov 	uMsg,0	; <-- reset ; bug fixed
	.elseif eax==WM_DESTROY		; ------- If Destroy ------- ;
		invoke PostQuitMessage,NULL
	.endif
	
@endl:
	invoke DefWindowProc,hWin,uMsg,wParam,lParam
	ret

WndProc endp

align 16

.data


.code	; ------- ENTRYPOINT ------- ;
;--------------------------------------------------------------------------------\
	                                                                             ;\
start:												; ------- Entry Point ------- ;|
                                                                                  ;/
                                                                                 ;/
;--------------------------------------------------------------------------------/

IFDEF 	RELEASE
	; ------- Initial First ------- ;
	call 	AnsavInitFirst
	call 	FillJunk
	
ENDIF
	; ------- process command line ------- ;
	call 	ProcessCommandLine
		
	; ------- Make sure memory is clean ------- ;
	.if 	!incmdl
		.if 	!NoScanMem
			call 	StartCheckMemoryFirst
		.endif
	.endif
	
	; ------- Make main window ------- ;
	.if 	!incmdl
		invoke  WinMain,hInstance,NULL,CommandLine,SW_SHOWDEFAULT
	.endif

GlobalExit::

	; ------- free last scanned path buffer ------- ;
	call 	FreeLastScannedPathBuffer

	; ------- free CmdLine buffer ------- ;
	mov 	eax,CmdLineScan
	cmp		eax,0
	je 		@F
		anfree 	eax
	@@:

	; ------- free exvdb is available ------- ;
	call 	CloseExVdb

	; ------- if stealth hook, free hook ------- ;
	call 	UnStealth
	
	; ------- immune registry ------- ;
	call 	RegImmune
	
	mov 	ebx,FreeLibrary
	
	; ------- unload all module ------- ;
	mov 	eax,hArcMod
	.if 	eax
		scall 	ebx,eax
	.endif

	mov 	eax,hFixerMod
	.if 	eax
		scall 	ebx,eax
	.endif
	
	; ------- unload plugins ------- ;
	call 	CleanupPlugins
	
IFDEF 	DEBUG
	; ------- Log needed ------- ;
	call 	CloseLog
ENDIF

IFDEF 	ERRORLOG
	; ------- Error Log needed ------- ;
	call 	CloseErrorLog
ENDIF
	
	push 0
	call ExitProcess
end start
