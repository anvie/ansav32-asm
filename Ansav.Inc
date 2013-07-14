; ------- Ansav.inc ------- ;

; ------- include files ------- ;
include windows.inc
include user32.inc
include kernel32.inc
include shell32.inc
include comctl32.inc
include comdlg32.inc
include advapi32.inc
include gdi32.inc

; ------- Library ------- ;
includelib user32.lib
includelib kernel32.lib
includelib shell32.lib
includelib comctl32.lib
includelib comdlg32.lib
includelib advapi32.lib
includelib gdi32.lib

; ------- Local inc * lib ------- ;
;include 	masm32.inc
;includelib  masm32.lib
include 	ctrl\txtColor\txtcolor.inc
includelib 	ctrl\txtColor\txtcolor.lib


MD5Checksum PROTO C

; ------- Global flags ------- ;
IFNDEF 	RELEASE
	DEBUG 				equ 1
ENDIF


	ERRORLOG			equ 1


; ------- PROTOTYPE ------- ;
WinMain				PROTO :DWORD,:DWORD,:DWORD,:DWORD
WndProc				PROTO :DWORD,:DWORD,:DWORD,:DWORD

; ------- define ------- ;
IDD_DIALOG				equ 1000
IDD_STARTUP				equ 1001
IDD_ABOUT				equ 1002
IDD_ANVDB				equ 1003
IDD_ANVDBBP				equ 1004
IDD_VIEWRESULT			equ 1005
IDD_MULTIPLEOBJECTSCAN	equ 1006
IDD_CONSOLELOG			equ 1007
IDD_VIEWQUARANTINE		equ 1008
IDD_CONFIGURATION		equ 1009
IDD_INSTALL				equ 1010
IDD_TRUSTZONE			equ 1011
IDD_UPDATE				equ 1012
IDD_SERVPASS			equ 1013
IDD_STATUS				equ 1014

IDI_MAIN_ICON		equ 500
BMPTHREATINFO		equ 600
IMG_LOGO_SMALL		equ 601
IMG_TBAR			equ 700
IMG_PISTOL			equ 701
IMG_BOOK			equ 702
IMG_VLOGO			equ 704
IMG_VREDTILE		equ 705
IMG_INSTALL 		equ 706

IMG_LOOP_SMALL		equ 800
IMG_LOOP_SMALL2		equ 801
IMG_SIKIL_SMALL		equ 802
IMG_BOOK_SMALL 		equ 803
IMG_GEMBOK_SMALL 	equ 804
IMG_HATI_SMALL 		equ 805
IMG_WARU_SMALL 		equ 806
IMG_PAPER_SMALL		equ 807
IMG_KUNCIINGGRIS_SMALL equ 808
IMG_FIXED_SMAL 		equ 809
IMG_REMOVABLE_SMALL	equ 810
IMG_CONSOLE_SMALL	equ 811
IMG_FOLDER			equ 812
IMG_JEMPOL_SMALL	equ 813
IMG_MEMORY_SMALL 	equ 814

; ------- Main Window Controls ------- ;
IDC_MAIN_LV			equ 1001
IDC_MAINTB_SCAN 	equ 2000
IDC_MAINTB_STOP		EQU 2001
IDC_MAINTB_CLEAN 	equ 2002
IDC_MAINTB_DELETE	equ 2003
IDC_MAINTB_QUARANTINE	equ 2004
IDC_MAINTB_VIEWRES	equ 2005
IDC_MAINTB_EXIT 	equ 2006
IDC_MAIN_PB			equ 1010
IDC_MAIN_TB 		equ 1017

IDC_TXT_STATUS 		equ 1002
IDC_TXT_CHKFILES	equ 1011
IDC_TXT_THREATDETC	equ 1012
IDC_TXT_PERCENT 	equ 1013

IDC_EDIT_PATH		equ 1007

; ------- Main Window Menu ID ------- ;
IDM_MAIN_MENU			equ 10000
IDM_FILE_SCAN			equ 10009
IDM_HELP_UPDATE 		equ 10010
IDM_FILE_SCAN2			equ 10008
IDM_FILE_SCANMEM		equ 10030
IDM_FILE_SCANMULTIPLEOBJECT EQU 10017
IDM_FILE_EXIT			equ 10001
IDM_ADVANCED_CONFIG		equ 10003
IDM_ADVANCED_ASHUT		equ 10019
IDM_TOOLS				equ 10005
IDM_VIEW_RESULT 		equ 10012
IDM_VIEW_CONSOLELOG		equ 10018
IDM_VIEW_QUARZONE		equ 10007
IDM_VIEW_VDB 			equ 10011
IDM_HELP_ABOUT			equ 10101
IDM_FILE_SCANALLHARDISK	equ 10015
IDM_FILE_SCANALLREM		equ 10016
IDM_FILE_SCANONLYWINDIR equ 10006
IDM_FILE_SCANSYSDIR		equ 10024
IDM_VIEW_CLEARLIST		equ 10026

IDM_HELP_INSTALL		equ 10021
IDM_HELP_README			equ 10022
IDM_HELP_SUBMITTHREAT	equ 10032
IDM_VIEW_TRUSTZONE		equ 10028

; ------- Startup Control dlg ------- ;
IDC_PROGBAR_STARTUP			equ 1001
IDC_STC_PERCENT				equ 1003
IDC_STC_PROCESSNAME			equ 1005

; ------- Status def ------- ;
STATUS_DETECTED			equ 1
STATUS_CLEAN			equ 2
STATUS_NOTTAKEACTION	equ 3
STATUS_TAKEACTION		equ 4
	
STATE_DISABLE 			equ 0
STATE_ENABLE			equ 1
	
.const ; ------- Constanta ------- ;

	szClassName			db 'HoneyKissMe',0
	;szAboutMsg			db "An's Antivirus",13,10,'Copyright © Ansoft 2006,2007',0
	
	
	; ------- viri Stuff Const ------- ;
	; Type --
	VIRI_JUNK 			equ 0
	VIRI_EXE			equ 1
	VIRI_COM			equ 2
	VIRI_DLL 			equ 4
	VIRI_VBS 			equ 8
	VIRI_MACRO			equ 16
	VIRI_BOOTSECTOR		equ 32
	VIRI_INFECTOR		equ 64
	VIRI_POLYMORPHIC	equ 128
	VIRI_STEALTH		equ 256
	VIRI_TROJAN			equ 512
	VIRI_METAMORPHIC	equ 1024
	VIRI_SUSPECTED		equ 2048
	
	; Flag --
	VIRI_F_CLEANABLE	equ 1
	VIRI_F_UNCLEANABLE	equ 0
	; RISK --
	VIRI_RISK_VERYLOW	equ 1
	VIRI_RISK_LOW		equ 2
	VIRI_RISK_MEDIUM	equ 3
	VIRI_RISK_HIGH		equ 4
	VIRI_RISK_VERYHIGH 	equ 5
	VIRI_RISK_DANGEROUS	equ 6
	
	IMAGE_FILE_NEUTRAL	equ 0
	IMAGE_FILE_EXE 		equ 100h
	FILE_TYPE_EXCLUDE	equ -1
	IMAGE_FILE_ZIP		equ 400h

	; ------- timer-timer ------- ;
	TMR_MONITOR_REMOVABLE	equ 3030
	
	
	UPDATE_AUTOCHECK	equ 2

.data? ; ------- Uninitialized Data ------- ;

	hInstance			dd ?
	CommandLine			dd ?
	hMainWnd			dd ?
	hMainList			dd ?
	WinVerNT			dd ?
	hMainPopMenu		dd ?
	incmdl				dd ?

	; ------- optimize ------- ;
	ShutdownAfterScan	dd ?
	

IFDEF 	DEBUG
	hFileLog			dd ?
ENDIF
IFDEF 	ERRORLOG 		
	ErrorOccured		dd ?
	hFileErrorLog		dd ?
ENDIF

	; ------- Path-path ------- ;
	szMyDir				db MAX_PATH+1 dup(?)
	szMyPath			db MAX_PATH+1 dup(?)
	szQuarantineDir		db MAX_PATH+1 dup(?)
	szWinDir 			db MAX_PATH+1 dup(?)
	szSysDir 			db MAX_PATH+1 dup(?)
	szTempDir 			db MAX_PATH+1 dup(?)
	szStartupDir 		db MAX_PATH+1 dup(?)
	szMyDocumentsDir	db MAX_PATH+1 dup(?)
	szTempFilePath		db MAX_PATH+1 dup(?)
	szAnsavIniPath 		db MAX_PATH+1 dup(?)
	szPluginsPath		db MAX_PATH+1 dup(?)
	szAnhookerPath		db MAX_PATH+1 dup(?)
	szAnsavTempWorkDir	db MAX_PATH+1 dup(?)
	szanPdetectorPath	db MAX_PATH+1 dup(?)
	szTrustDataPath 	db MAX_PATH+1 dup(?)
	szSteDll2			db MAX_PATH+1 dup(?)	; <-- generate it ;

	; ------- Misc ------- ;
	PackerIs			dd ?
	HaveMMX				dd ?
	CleanInArc 			dd ?
	SomeObjectNeedReboot dd ?
	AlreadyInstalled	dd ?
	hFixerMod			dd ?
	FixerReady			dd ?
	FixerClean			dd ?
	ForFix				dd ?
	brw					dd ?
	brw2				dd ?
	rect				RECT <> 
	ScanLogBuffer 		db 1024+1 dup (?)
	ClrBrushBlack		dd ?
	ClrBrushBlack2		dd ?
	cpack				dd ?
	szRandomString		db 256 dup(?)
	TimeForBlind		dd ?
	DebugDetcL1			dd ?
	DebugDetcL2			dd ?
	_IsCanHook?			dd ?
	hAnpDetector		dd ?
	ExternalVdb			dd ?
	ExternalVdbSize 	dd ?
	NoStealth			dd ?
	AnsavGuardActive	dd ?
	FileScanAborted		dd ?
	ExplorerPID			dd ? 	; <-- exclude this proc from LoadLibraryEx ;
	EnableArchiveScan	dd ?
	ZIP					dd ?
	JAR 				dd ?
	LimitArcSize		dd ?
	LimitArcSizeTS		dd ?
	DontAskDelSusp		dd ?
	hAutUpdCheckThread	dd ?
	CmdLineScan			dd ?
	
	; ------- used for scanning ------- ;
	WORKFILE	struct
		hFile 			dd ?
		fSize			dd ?
		fMap 			dd ?
		lpVoidMem		dd ?
		FileType		dw ?
	WORKFILE ends
	ScannableFileObject		WORKFILE <>
	
	pBufferVirusInfo			dd ?
	BufferVirusInfoSize			dd ?
	BufferVirusInfoItemCount	dd ?
	MemCheck					dd ?
	SingleCheck					dd ?
	StopScan					dd ?
	StopClean					dd ?
	TimeBeginScan				SYSTEMTIME <>
	TimeEndScan 				SYSTEMTIME <>
	TimeTakeA					SYSTEMTIME <>
	_ZwOpenProcess				dd ?
	_WhatThePackerEx			dd ?
	_PackerType2String			dd ?
	
	VIRUSINFO 	struct
		dwType 			WORD ?	; ------- .EXE, .DLL, .VBS, Poly, Meta, etc ------- ;
		dwCleanable		WORD ?	; ------- Infected, or Single Worm ------- ;
		Risk			WORD ?  ; ------- Low, Med, High ------- ;
		Description		DWORD ?
	VIRUSINFO ends
	
	THREATFULLINFO struct
		szFilePath		db MAX_PATH+1 dup(?)
		fSize			dd ?
		dwAttribute		dd ?
		szThreatName	db 30 dup (?)
		lpszInfo		dd ?
		uVirusInfo		VIRUSINFO <>
	THREATFULLINFO ends
	
	; ------- VDB struct ------- ;
	SVDBv2 struct
		szVirusSign		db 30 dup (?) 	; ------- For virus sign ------- ;
		dwSignLength	dd ?			; ------- For length of virus sign ------- ;
		dwSignOffset	dd ?			; ------- For first offset of sign ------- ;
		szThreatName	db 30 dup (?)	; ------- For virus name ------- ;
		dwUniqueID		dd ?
		fOnlyShow		dw ?
		uVirusInfo		VIRUSINFO <>	; ------- For more info about this virus ------- ;	
	SVDBv2 ends
	; ------- SVDBv2 usage sample ------- ;
	
	PLAINCODE struct
		lpszPlain dd ?
		Len dd ?
		szthName db 30 dup(?)
		vinfo VIRUSINFO<> 
	PLAINCODE ends

	
	; w32_trafox_virus	SVDBv2 <"TRAFOXASIC",10,10345,"W32.Trafox.A",<0FH,1>>  
	
	; ------- End of SVDBv2 sample ------- ;
	
	SECTION_ALLWOVL equ 0
	SECTION_BSS 	equ 1
	SECTION_CODE 	equ 2
	SECTION_ENTRYP	equ 4
	SECTION_WRITABLE equ 8
	SECTION_DATA	equ 16
	SECTION_RESOURCE equ 32
	SECTION_ALLNOVL equ 64
	SECTION_NOTSEARCH equ 128
	SECTION_RDATA	equ 256
	
	SIAVDBv2	struct
		szThreatName	db 30 dup (?)
		dwVDBLength		dd ? ; ------- Sia lpSiaData Length ------- ;
		bSiaExcluder	db ? ; ------- Byte Excluder ------- ;
		lpSiaData		dd ? ; ------- Sia Offset ------- ;
		lpSection		dd ?
		uVirusInfo		VIRUSINFO <>
		; optimized
	SIAVDBv2 ends
	
	; ------- SIAVDBv2 usage sample ------- ;
	
	;SIA_W32_AKSIKA		db 0,0,0,0,0,0,0,0,0,0,0
	;FirstSIA			SIAVDBv2 <11,77h,offset SIA_W32_AKSIKA> 	 
	
	; ------- End of SIAVDBv2 sample ------- ;
	
	ANSAVAIVDBv2	struct
		szSuspectName	db 30 dup (?)
		lpszInfo		dd ?
		lpData			dd ?
		dwDataSize		dd ?
		iSize			dd ?
	ANSAVAIVDBv2 ends
	

	
	LASTSCANNEDINFO	struct
		szLocation			db MAX_PATH+1 dup(?)
		dwFileScanned 		dd ?
		dwThreatsDetected	dd ?
		wStatus				dw ? 	; <-- cleaned or not take action ;
		wFinished			dw ?
		lpFailedArray		dd ?
	LASTSCANNEDINFO ends
	
	; quarantine file style structure
	ANQ_IMAGE_HEADER	struct
		AnqSignature	db 4 dup (?)
		dwPackSize		dd ?
		lpThInfo 		THREATFULLINFO <>
		Index			dd ?
	ANQ_IMAGE_HEADER ends
	
	AnqImageHeader			ANQ_IMAGE_HEADER <>
	
	LastScannedInfo 		LASTSCANNEDINFO <>
	LastScannedPath 		dd ?
	LastScannedPathSize		dd ?

	LastPercentValue		dd ?
	AllFilesCount			dd ?
	InScanning				dd ?
	InAction				dd ?
	MainPBPos				dd ?
	szCheckedFilesCountBuff	db 1024 dup(?)
	szDetectedThreatCntBuff	db 1024 dup(?)
	szPercentBuff			db 10 dup(?)
	gTFI					THREATFULLINFO <>
	szScanBuff				db (MAX_PATH*4)+4 dup(?)

	

	EXVDBINFO	struct
		eMagic 	dw ?
		wYear	dw ?
		wMonth  dw ?
		wDay 	dw ?
		dwVerM	dd ?
		dwVerN	dd ?
		dwVerO	dd ?
		RealSize dd ?
	EXVDBINFO ends

	CEST	STRUCT
		pRvd dd ?	; <-- 0h ;
		hPID dd ?	; <-- 04h ;
		hTHID dd ? 	; <-- 08h ;
		hWnd2 dd ?	; <-- 0Ch ;
		hMainWnd dd ?	; <-- 10h ;
		hServPID dd ?
		hServPID2 dd ?
	CEST 	ends
	
	hStealthHook dd ?
	hStealthHookMod dd ?
	hStealthfMap dd ?
	hStealthmMap dd ?

	; ------- Data for main wnd ------- ;
	UnpackedData		dd ?
	hVLogoBmp			dd ?
	hImgThreatInfo		dd ?
	hBmpThreatInfo		dd ?
	hMainTxtStatus		dd ?
	hMainEditPath		dd ?
	hMainMenu			dd ?
	hTxtStatusClean		dd ?
	hTxtStatusDetc		dd ?
	hMainProgBar		dd ?
	hToolBar			dd ?
	hTbBmp				dd ?
	TTLTimerCounter		dd ?
	hMainIcon			dd ?
	hMnuScan			dd ?
	hTxtCheckedFiles	dd ?
	hTxtMainPercent		dd ?
	hTxtDetectedThreats	dd ?
	DetectedThreatsCnt 	dd ?

	icex 				INITCOMMONCONTROLSEX <>
	
	; ------- Data for Startup dlg ------- ;
	hDlgStartup			dd ?
	hStartupProgbar		dd ?
	dwPBMaxValue		dd ?

	; ------- Data for about dlg ------- ;
	hTxtAboutInfo		dd ?

	; ------- Data for Quarantine dlg ------- ;
	hQuarantineDlg 		dd ?
	hListQuarantine		dd ?
	hViewQuarDlgPopMenu	dd ?
	
	; ------- Data for Console log dlg ------- ;
	hConsoleLogDlg 	dd ?
	hTxtConsoleLog 	dd ?
	ScanLogReady 	dd ?
	lpTxtConsoleLog	dd ?

	
	; ------- CONFIGURATION ------- ;
	ScanLevel 		dd ?
	NoBipServ 		dd ?
	NoDetcSound1 	dd ?
	NoDetcSound2 	dd ?
	MainScanButton 	dd ?
	NoFQC			dd ?
	NoScanMem 		dd ?
	ShowResult 		dd ?
	NoActConfirm 	dd ?
	ShowLog 		dd ?
	NoPlugins 		dd ?
	EnableAngd		dd ?
	SaveLS			dd ?
	StealthMode		dd ?

.data				; --------------------[ -= INITIALIZED DATA SECTION =- ]

	szAppName			db "ANSAV +E Advanced", 30 dup(0), 0	; <-- need for modify ;
	
	
IFDEF 	DEBUG
	szFileLog 		db "log.txt",0
ENDIF
IFDEF 	ERRORLOG
	szFileErrorLog	db "error.log",0
ENDIF
	
	; ------- String Format ------- ;
	szPercentF 		db '%d %%',0
	szdTosF			db '%d',0
	szVdbVerF		db 'Updated %d.%d.%d',0
	szQfNameStyleF	db "%d_anQ",0
	
IFDEF 	ERRORLOG
	szErrorMsgLogFile	db "---------------------------------------------------------------------------",13,10
						db " This error log file generated automaticaly by Ansav system error handler         ",13,10
						db " this file contains any information about error, bug  or  incompatibility         ",13,10
						db " Ansav with your system.                                                          ",13,10
						db " If You see this file please send this file to  Ansav author for  further         ",13,10
						db " analysis.",13,10
						db 13,10
						db "     [4NV|e]",13,10
						db "     anvie_2194 @ ansav.com",13,10
						db "---------------------------------------------------------------------------",13,10
						db 13,10,0
	szWindowsVersionF 	db "  Windows Version %d.%d Build %d Service Pack %d.%d",13,10,13,10,0
	szErrorLogF			db 13,10
						db "[%d:%d:%d] ERROR occured!, ",13,10,"Error Code %d, %s",0
	szErrorContextF		db "In %s",13,10
						db "Technical Information :",13,10
						db " |                     EIP = %ph  EAX = %ph",13,10
						db " |                     EDI = %ph  ESI = %ph",13,10
						db " |                     ECX = %ph  EDX = %ph",13,10
						db " |                     EBX = %ph  ESP = %ph",13,10
						db " |                     EBP = %ph",13,10
						db " |",13,10
						db " +-------------------> Offset %d from [ %s ]-->%s",13,10,0
	szErrorLogAnsavVersionF		db "  Ansav +E Advanced Version : %d.%d.%d",13,10
								db "  Last Updated %d.%d.%d",13,10,13,10,0
	szCrlf				db 13,10,0
ENDIF
	
	szSparator 		db "---------------------------------------------------------------------------",13,10,0

        szSDP       db "SeDebugPrivilege",0
        szAdvapi    db "advapi32.dll",0
                    db "AdjustTokenPrivileges",0
                    db "InitializeAcl",0
                    db "LookupPrivilegeValueA",0
                    db "OpenProcessToken",0
                    db "SetSecurityInfo",0,0
                    
	; ------- file-file dir-dir ------- ;
	szQuarDirName	db "Quarantine",0
	szNtdll			db "ntdll.dll",0
	szTempResultFileName 	db "result.log",0
	szTempScanLog	db "ansav.log",0
	szAnhookerDll	db "an32hk.dll",0
	szanPdetectordll db "anPdetector.dll",0
	szAgd32sys		db "agd32.sys",0
	szVdbDat 		db "vdb.dat",0
	szArcdll 		db "arc.dll",0
	szFixerFx		db "fixer.fx",0
	szTrustDataFile db "trustzone.dat",0
	szSteDll		db "ste.dll",0
	
	; ------- Api-Api ------- ;
	szZwOpenProcess	db "ZwOpenProcess",0
	
	szInstallHook	db "InstallHook",0
	szUninstallHook db "UninstallHook",0
	szDllGetVersion	db "DllGetVersion",0
	sz__lsp		db "__lsp",0
	sz__lsf		db "__lsf",0
	sz__setne 	db "__setne",0
	sz__ghpd	db "__ghpd",0
	sz__ret32	db "__ret32",0
	sz__dhm		db "__dhm",0		; <-- DON'T HOOK ME ;
	sz__isao32 	db "__isao32",0	; <-- IS API OKAY? ;
	sz__cest	db "__cest",0
	szWhatThePackerEx db "WhatThePackerEx",0
	szPackerType2String db "PackerType2String",0
	
	; ------- Reg ------- ;
	szExeDefault    db '"%1" %*',0
	szRegExt    	db '%s\shell\open\command',0
	
	; ------- Scan stuff ------- ;
	szImportantExt	db 'exe',0,'scr',0,'doc',0,'odt',0,'xls',0,'txt',0,'jpg',0,'jpeg',0,'gif',0,'bmp',0,'avi',0,'rtf',0
					db 'mpg',0,'mpeg',0,'mp4',0,'mp3',0,'wav',0,'opt',0,'eml',0,'htm',0,'html',0,'xml',0,'rar',0,'ppt',0
					db 'zip',0,'cmd',0,'gzip',0,'tar',0,'cab',0,'pdf',0,'com',0,'pif',0,'bat',0,'3gp',0,'wma',0,0
	
	szMaskTxt 		db "Text file",0,"*.txt",0,0
	szMaskAllFile	db "All file",0,"*.*",0,0
	szSuspected1	db "Potentially harmfull",0
	szRiskVeryLow	db "Very Low",0
	szRiskLow		db "Low",0
	szRiskMedium	db "Medium",0		
	szRiskHigh		db "High",0
	szRiskVeryHigh	db "Very High",0
	szRiskDanger	db "Dangerous",0
	szUnknown		db "Unknown",0
	szAllHardisk 			db "All hardisk",0
	szAllRemovableMedia 	db "All removable media",0
	szInMemory				db "Memory processes",0
	szSingleScan			db "Single scan file",0
	szFakeExt		db "Fake extention detected.",0
	
	szYouHaveThreat	db "You not take action for last detected threat(s), if You make new scan ",13,10
					db "all information for last detected threat(s) will be lost. are You sure?",0
	
	; ------- Info ------- ;
	szDetectedInMem	db "Resident In Memory.",0
	szError			db "ERROR",0
	
	; ------- data for main wnd ------- ;
	szToolbarWindow32	db "ToolbarWindow32",0
	szScan				db "Scan",0
	szStop				db "Stop",0
	szClean				db "Clean",0
	szDelete 			db "Delete",0
	szQuarantine 		db "Quarantine",0
	szViewResult 		db "Result",0
	szExit 				db "Exit",0
	szStatusIdle		db "[ Idle ]",0
	szStatusBuffering 	db "[ Buffering... ] - Please wait...",0
	szStatusChecking	db "[ Checking... ]",0
	szStatusCleaning	db "[ Cleaning... ]",0
	szStatusStoped		db "[ Stoped ]",0
	szKosong			db 0,0
	szNullPercent		db '0%',0
	szNull 				db '0',0
	szWaitForCmd		db "Wait for command...",0
	;szNotCStoped		db "Process stopped by user.",0
	szCheckComplete		db "Checking Completed!",0
	szComplete			db "  [ COMPLETE ]",0
	szCheckStoped		db "Operation aborted by user",0
	
	; ------- DATA for config wnd ------- ;
	;szStop				db "Stop",0
	szActivate			db "Activate",0
	
	; ------- type-type ------- ;
	szViriExe			db "EXE",0
	szViriCom   		db "COM",0
	szViriDLL			db "DLL",0
	szViriVbs			db "VBS",0
	szViriMacro 		db "MACRO",0
	szViriBootSector 	db "Bootsector",0
	szViriTypeVirus	 	db "Virus",0
	szViriTypeWorm	 	db "Worm",0
	szViriTypeTrojan	db "Trojan",0
	szViriTypeVW		db "Worm/Virus",0
	szViriJunk			db "Junk",0	
	
	; ------- Misc ------- ;
	szTrayClass 		db "AnsavTrayWnd32",0
	szSteKey 			db "XHASH",0
	szThreatInsideF		db "%d Threat(s) inside",0
	szInsideArc			db "Inside archive file",0
	sztt2				db ':',0
	szReadmeTxt 		db "readme.txt",0
	szAnsavgd 			db "ansavgd",0
	AnsavMsgHookCode	dd 2194h
	szExplorer			db "explorer.exe",0
	szBrw				db "_q_",0
	szStrip				db "-",0
	szOpen				db "open",0
	szInitSuckses 		db "Initialize SUCCESS",0
	szInitFailed 		db "Initialize FAILED",0
	szInitCompleted		db "Initialize COMPLETED",0
	szScanLogReady 		db "SCAN LOG READY...",0
	szFlushBuffer 		db "Flush buffer...",0
	szFreeMem			db "Free memory...",0
	szSuccess			db " [ SUCCESS ]",0
	szFailed 			db " [ FAILED ]",0
	szDone				db " [ DONE ]",0
	szBuffering			db "Buffering...",0 
	szChecking 			db "Checking...",0
	szCheckThisDir 		db "Checking this dir :",0
	szCheckThisFile 	db "Checking this file :",0
	szInitSLS 			db "Initializing SLS",0
	szAllocMemForDrv	db "Allocating memory for mapping drive(s)...",0
	szCheckCmpltDC		db "Operation ended, some threat detected!",0
	szCheckCmpltNDC		db "Operation ended, threat not detected",0
	szOperationAbort	db "Operation aborted...",0
	szThisFile 			db "This file :",0
	szThisPath			db "This path :",0
	szThisObject		db "This object :",0
	szDetectedUsesL1	db " -> object suspected in detection uses level 1",0
	szDetectedUsesL2	db " -> object detected as threat in detection uses level 2",0
	szDetectedUsesL3	db " -> object detected as threat in detection uses level 3",0
	szDetectedUsesL4	db " -> object detected as threat in detection uses level 4",0
	szOLnotEx			db "Old location to restore object does not exist",13,10
						db "do You want to restore in another location?",0
	szObjSuspectedF		db "This object is suspected :",13,10
						db '"%s "',13,10
						db "it's mean object uncleanable.",13,10
						db "Available action for uncleanable object is delete or quarantine,",13,10
						db 'click "Yes" to delete it.',0
	szMemAllocError		db "Memory can't allocated!",0
	szUncleanNdtrbF		db "%d Uncleanable threat(s) object will be delete after system reboot.",13,10
						db "Do you want to reboot your computer now?",0
	szPleaseSave 		db "Please save all your unsaved work and press ok to reboot computer.",0 
	szLatestUpdF 		db "ANSAV was updated succesfully at %d-%d-%d",13,10
				 		db "from version : %d.%d.%d to version : %d.%d.%d",13,10
				 		db "Known threats in this version is : %d threats (include external)",0
	szAnupdCache		db "updch.tmp",0
	szMediaNW 			db "Media unwriteable or write protected.",0

	; ------- error ------- ;
	szErrMem db "Allocate memory error..",0
	
	szAnsavIni			db "ansav.ini",0
	szAnsavName			db "ANSAV",0
	
	TbrArr				TBBUTTON <0,IDC_MAINTB_SCAN,TBSTATE_ENABLED,TBSTYLE_BUTTON,0,0,offset szScan>
						TBBUTTON <1,IDC_MAINTB_STOP,TBSTATE_ENABLED,TBSTYLE_BUTTON,0,0,offset szStop>
						TBBUTTON <0,0,TBSTATE_ENABLED,TBSTYLE_SEP,0,0>
						TBBUTTON <2,IDC_MAINTB_CLEAN,TBSTATE_ENABLED,TBSTYLE_BUTTON,0,0,offset szClean>
						TBBUTTON <3,IDC_MAINTB_DELETE,TBSTATE_ENABLED,TBSTYLE_BUTTON,0,0,offset szDelete>
						TBBUTTON <4,IDC_MAINTB_QUARANTINE,TBSTATE_ENABLED,TBSTYLE_BUTTON,0,0,offset szQuarantine>
						TBBUTTON <0,0,TBSTATE_ENABLED,TBSTYLE_SEP,0,0>
						TBBUTTON <5,IDC_MAINTB_VIEWRES,TBSTATE_ENABLED,TBSTYLE_BUTTON,0,0,offset szViewResult>
						TBBUTTON <0,0,TBSTATE_ENABLED,TBSTYLE_SEP,0,0>
						TBBUTTON <6,IDC_MAINTB_EXIT,TBSTATE_ENABLED,TBSTYLE_BUTTON,0,0,offset szExit>
	TbrArrCnt			equ 10
                    
.code ; ------- Code Section ------- ;


; ------- SCONDARY PROTOS ------- ;
;
;; ------- from  : inc\Registry.asm ------- ;
SetRegString  	PROTO :DWORD, :DWORD, :DWORD, :DWORD
GetRegString 	PROTO :DWORD, :DWORD, :DWORD, :DWORD
DeleteKeyValue 	PROTO :DWORD, :DWORD, :DWORD
SetRegDword 	PROTO :DWORD, :DWORD, :DWORD, :DWORD
GetRegDword 	PROTO :DWORD, :DWORD, :DWORD, :DWORD
; -------------- ;

; ------- from : inc\utils_ansav.asm ------- ;
OnlyFileName 		PROTO :DWORD,:DWORD
OnlyPathDir 		PROTO :DWORD
FileExist 			PROTO :DWORD
PercentThis 		PROTO :DWORD,:DWORD
GetProcessPath 		PROTO :DWORD,:DWORD,:DWORD
GetNumAllProcesses 	PROTO
SetToken 			PROTO 			
SetPrivileges 		PROTO 
TruePath 			PROTO :DWORD
MyZeroMemory 		PROTO :DWORD,:DWORD
MyCopyMem			PROTO :DWORD,:DWORD,:DWORD
SetBmpColor 		PROTO :DWORD
KillObjectForcely 	PROTO :DWORD
IsDriveNW 			PROTO :DWORD
; -------------- ;

; ------- from : inc\AnsavStuff.asm ------- ;
GetPathPath 		PROTO 		
IsRunnable 			PROTO :DWORD
LvInsertTFIItem		PROTO :DWORD
InitScan			PROTO
InsertLastScannedPathBuffer	PROTO :DWORD
SaveResult 			PROTO :DWORD
UpdateArcItemList 	PROTO :DWORD
ClipboardCopyObject PROTO :DWORD
; -------------- ;

; ------- from : inc\engine.asm ------- ;
CheckThisFile 		PROTO :DWORD,:DWORD ;,:DWORD
; -------------- ;

; ------- from: inc\maindlgctrl.asm ------- ;
SetMainTxtStatus2 	PROTO :DWORD,:DWORD
SetMainTxtStatus 	PROTO :DWORD
SetCtrlDS 			PROTO :DWORD
SetActionTbState 	PROTO :DWORD
IsObjectExistsInList?	PROTO :DWORD
IsArchiveRoot? 		PROTO :DWORD
; -------------- ;

; ------- from inc\Memory.asm ------- ;
IsRunInMemory?		PROTO :DWORD
; -------------- ;

; ------- from inc\bffolder.asm ------- ;
BrowseForFolder 	PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
; -------------- ;

; ------- from inc\ConsoleLog.asm ------- ;
AppendLogConsole 	PROTO :DWORD
; -------------- ;

includelib 	inc\aPlib.lib
; ------- from inc\aPlib.lib ------- ; uses for compress all quarantined object
aP_pack            PROTO c, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
aP_workmem_size    PROTO c, :DWORD
aP_depack_asm      PROTO c, :DWORD, :DWORD
aP_depack_asm_fast PROTO c, :DWORD, :DWORD
; -------------- ;

; ------- from inc\quarantine.asm ------- ;
DoQuarantineThis   	PROTO	:DWORD,:DWORD,:DWORD
InitQuarantine     	PROTO
GetFQInfo 			PROTO 	:DWORD,:DWORD
RestoreFQ 			PROTO	:DWORD,:DWORD
; -------------- ;

; ------- from inc\heuristic.asm ------- ;
CheckUsesAnsavai 	PROTO 	:DWORD
; -------------- ;

; ------- from inc/install.asm ------- ;
IsAlreadyInstalled?	PROTO
; -------------- ;

; ------- from inc/service.asm ------- ;
SetServiceStartType PROTO :DWORD
; -------------- ;

; ------- from inc/trustzone.asm ------- ;
IsTrusted 	PROTO :DWORD,:DWORD
; -------------- ;

; ------- from inc/boyer.asm ------- ;
BMBinSearch PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
; -------------- ;

; ------- from inc/lingo.asm ------- ;
InStringL PROTO :DWORD, :DWORD
; -------------- ;

IFDEF 	ERRORLOG
	; ------- from : inc\debug.asm ------- ;
InitErrorLog 	PROTO
ErrorLog 		PROTO :DWORD
CloseErrorLog 	PROTO

ENDIF

; ------- SPECIAL MACRO FOR DEBUGGING ------- ;
mErrorLog 	MACRO arg
	LOCAL 	nustr
IFDEF 	ERRORLOG
	quot  SUBSTR <arg>,1,1
	push 	eax
	IFIDN	quot,<">
	.data
		nustr 	db arg,13,10,0
	.code
	; ------- Save EAX ------- ;
	lea 	eax,nustr
	push 	eax
	ELSE
	push 	arg
	ENDIF
	call 	ErrorLog
	; ------- Restore EAX ------- ;
	pop 	eax
ENDIF
endm

.data?
	szErrorDump	db 512 dup (?)
.code

ErrorDump MACRO  gps,lpVoidProc,ParentFile
	LOCAL 	nustr,nustr2,lp1,lp2
IFDEF 	ERRORLOG

	quot SUBSTR <ParentFile>,1,1
	.data
		nustr 	db gps,0
	.code
	
	IFIDN	quot,<">
	.data
		nustr2  db ParentFile,0
	.code
	ENDIF

	 ; ------- fix stack ------- ;
	 ; unhandled exception bug fixed
	 lp1:
		mov 	eax,[esp-0314h]
		and 	eax,0FF000000h
		jz 		@F
		shr		eax,24
		@@:
		sub 	esp,04h
		cmp 	al,07Ch
		jne 	lp1
		add 	esp,4*5
	 ; -------------- ;
	
	mov 	edi,dword ptr ss:[esp-0314h] ; ------- Get context ------- ;
	
	assume 	edi:ptr CONTEXT
	;analloc 	512 ; ------- Get error information ------- ;
	mov 	eax,offset szErrorDump
	.if 	eax
		mov 	esi,eax
		
		; ------- Fix some reg ------- ;
		;mov 	ebp,[edi].regEbp
		mov 	eax,[edi].regEax
		mov 	ecx,[edi].regEcx
		
		lea 	eax,nustr
		push 	eax
		IFIDN	quot,<">
		lea 	eax,nustr2
		push 	eax
		ELSE
		push 	ParentFile
		ENDIF
		; ------- Get error line code in bytes ------- ;
		mov 	ecx,[edi].regEip
		sub 	ecx,lpVoidProc
		push 	ecx
		; ------- Dump all last context ------- ;
		push 	[edi].regEbp
		push 	[edi].regEsp
		push 	[edi].regEbx
		push 	[edi].regEdx
		push 	[edi].regEcx
		push 	[edi].regEsi
		push 	[edi].regEdi
		push 	[edi].regEax
		push 	[edi].regEip
		lea 	eax,nustr
		push 	eax
		lea 	eax,szErrorContextF
		push 	eax
		push 	esi
		call 	wsprintf
		add 	esp,4*15
		
		mErrorLog   esi ; ------- Save it to error log file ------- ;
		
		;anfree 	esi
	.endif
	
	assume 	edi:nothing

ENDIF
ENDM

mErrorTrap MACRO tTester, arg, so
IFDEF 	ERRORLOG
	test 	tTester,tTester
	.if 	zero?
		mErrorLog	arg
		quot SUBSTR <so>,1,1
		IFDIF 	quot,<0>
		jmp 	so
		ENDIF
	.endif
ENDIF
endm

mWriteError	MACRO	arg
	LOCAL 	nustr
IFDEF 	ERRORLOG
	quot 	SUBSTR	<arg>,1,1
	IFIDN	quot,<">
		.data
			nustr 	db arg,0
		.code
		push 	offset nustr
	ELSE
		push 	arg
	ENDIF
	call 	WriteError
ENDIF
endm

; -------------- ;

.code
; ------ external function ------- ;
include 	inc\version.asm
include 	inc\anmac.asm
include 	inc\peoperations.asm

; ------- Primary files include ------- ;
include 	inc\VirusDB.asm	; ----- Virus DataBase for Ansav New ;
; -------------- ;
IFDEF 	DEBUG
;LOOP_COUNT 	EQU 1000000
include 	inc\timers.asm ; used for testing speed
ENDIF

include 	inc\boyer.asm
include 	inc\lingo.asm
include 	inc\String.asm
include 	inc\driver.asm
include 	inc\vbs.asm
include 	inc\Registry.asm
include 	inc\vtile.asm
include 	inc\bffolder.asm
include 	inc\arc.asm
include 	inc\utils_ansav.asm

; ------- generic unpacker ------- ;
include 	inc\unpacker\upx.asm			; UPX Markus Lazzlo molnar
include 	inc\unpacker\aspack.asm			; ASPack Alexey S
include 	inc\unpacker\fsg.asm			; FSG v2.0 Bart/xt
include 	inc\unpacker\lzma_unpack.asm	; LZMA stuff Igor pavlov 
include 	inc\unpacker\pecompact2.asm 	; PECompact Jeremy C
; -------------- ;

include 	inc\AnsavStuff.asm
include 	inc\engine.asm
include 	inc\Memory.asm
include 	inc\Maindlgctrl.asm
include		inc\aboutdlg.asm
include 	inc\AnvdbDlg.asm
include 	inc\ViewResultDlg.asm
include 	inc\multiplescan.asm
include 	inc\consolelog.asm
include 	inc\Quarantine.asm
include 	inc\ViewQuarantineDlg.asm
include 	inc\heuristic.asm
include 	inc\anPdetector.asm
include 	inc\Plugins.asm
include 	inc\regimmune.asm

IFNDEF 		RELEASE
include 	inc\rtg.asm
ENDIF

include 	inc\Config.asm
include 	inc\trustzone.asm
include 	inc\network.asm
include 	inc\update.asm
include 	inc\servpass.asm
include 	inc\polyjunk.asm

; ------- Installation ------- ;
include 	inc/Install.asm
; -------------- ;







