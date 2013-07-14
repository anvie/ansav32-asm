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


;-------------------------------------- Install.asm ----------------------------------------;
.data?
	hInstallWnd		dd ?
	InstPos 		dd ?
	hListInstall	dd ?
	TestOkay		dd ?
	InTest			dd ?
	InstalAbort		dd ?
	FailedStub		dd ?
	hInstallPB		dd ?
	RoolBack		dd ?
	CreateShortcut	dd ?
	NeedRestart		dd ?
	Selesai			dd ?
	InstError		dd ?
	Uninstall		dd ?
	szInstallBuff	db 1024 dup(?)
	szInstallBuff2	db 1024 dup(?)
	lpszFailedBuff	dd ?
	szInstallLocation db MAX_PATH+1 dup(?)
.data
	szInstallTitle db "ANSAV Installation Wizard",0
	szSeparator2 db 100 dup ('-'),0
	szOk		db "[ OKE ]",0
	szGagal		db "[ GAGAL ]",0
	szInsMsg01 	db "Sebelum memulai proses pemasangan, ANSAV akan terlebih dahulu memeriksa "
				db "kompatibilitas komputer Anda dengan beberapa komponen ANSAV. ",13,10
				db 'Hal ini sangat penting, mengingat beberapa sepsifikasi komputer '
				db 'tidak dapat menjalankan Ansav Guard dengan baik. Sehingga, selain '
				db 'sebagai syarat kelayakan, juga sebagai bahan pengembangan ANSAV selanjutnya.',13,10,13,10
				db "Disini bahasa Indonesia sengaja digunakan melihat user terbanyak "
				db "berasal dari Indonesia, sehingga akan lebih mudah dipahami bagi yang masih awam sekalipun."
				db "Tetapi jika bahasa asing semisal Inggris "
				db "yang Anda harapkan bisa Anda baca pada dokumentasi ANSAV yang "
				db "telah diikutsertakan.",13,10,13,10
				db 'Untuk melanjutkan proses pemasangan klik "Lanjut", sebaliknya '
				db 'klik "Batal" untuk membatalkannya.',0
	szUninstallMsg	db 'Tidak ada prosedur lain untuk melakukan uninstall, '
					db 'selain..., klik saja tombol "Uninstall" di bawah ini '
					db 'dan ANSAV akan ter-uninstall secara otomatis.',0
	szRegserv	db "SYSTEM\ControlSet001\Services",0
	szInstalledEx	db "InstalledEx",0 
	szPlugins 	db "Plugins",0
	szShellFolder	db "Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",0
	szCommonDesktop db "Common Desktop",0
	szPlusEAlnk	db "Ansav +E Advanced.lnk",0
	szGagalExtractAgd db "Gagal mengekstrak beberapa komponen Ansav Guard.",13,10
					  db "Coba hidupkan ulang komputer anda terlebih dahulu, lalu ulangi lagi.",0
.code

include 	inc/Admin.asm

Align 16

rgb MACRO red,green,blue
	
	xor 	eax,eax
	mov 	al,blue
	shl 	eax,8
	mov 	al,green
	shl 	eax,8
	mov 	al,red
	
	EXITM <eax>

ENDM

Align 16

IsAlreadyInstalled? proc uses edi esi 
	LOCAL 	sest:SERVICE_STATUS
	LOCAL	retv:DWORD
	
	; ------- seh installation ------- ;
	SehBegin 	__iai?
	
	mov 	retv,0
	invoke 	OpenSCManager,0,0,SC_MANAGER_ENUMERATE_SERVICE
	.if 	eax
		mov 	esi,eax
		
		invoke 	OpenService,esi,ADDR szAnsavgd,SERVICE_QUERY_STATUS
		.if 	eax
			mov 	edi,eax
			
			invoke 	QueryServiceStatus,edi,ADDR sest 
			mov 	retv,eax
			
			invoke 	CloseServiceHandle,edi
		.else
			call 	GetLastError
			.if 	eax != ERROR_SERVICE_DOES_NOT_EXIST
				mov 	eax,1
			.endif
		.endif
		invoke 	CloseServiceHandle,esi
	.endif
	
	; ------- seh trapper ------- ;
	SehTrap 	__iai?
		ErrorDump	"IsAlreadyInstalled?",offset IsAlreadyInstalled?,"Install.asm"
	SehEnd 		__iai?
	
	mov 	eax,retv
	ret

IsAlreadyInstalled? endp 

Align 16

SetInstMsg proc idc:DWORD,lpMsg:DWORD
	
	invoke 	GetDlgItem,hInstallWnd,idc
	invoke 	SetWindowText,eax,lpMsg
	
	ret

SetInstMsg endp

Align 16

AddInstMsg proc lpMsg:DWORD,delay:DWORD

	invoke 	GetDlgItem,hInstallWnd,1009
	invoke 	SendMessage,eax,LB_ADDSTRING,0,lpMsg
	call 	InstListCount
	invoke 	SendMessage,hListInstall,LB_SETCURSEL,eax,eax
IFDEF 	RELEASE
	invoke 	Sleep,delay
ELSE
	invoke 	Sleep,50
ENDIF
	ret

AddInstMsg endp

Align 16

SubInstMsg proc lpMsg:DWORD
	LOCAL 	lBuff[250]:BYTE
	
	invoke 	MyZeroMemory,ADDR lBuff,250
	call 	InstListCount
	mov 	edx,eax
	invoke 	SendMessage,hListInstall,LB_GETTEXT,edx,ADDR lBuff
	
	lea eax,lBuff
	strlen eax
	
	mov		word ptr lBuff[eax],' -'
	invoke 	lstrcat,ADDR lBuff,lpMsg
	call 	InstListCount
	invoke 	SendMessage,hListInstall,LB_DELETESTRING,eax,eax
	invoke 	AddInstMsg,ADDR lBuff,500
	
	ret

SubInstMsg endp

Align 16

ThreadCall	proc pAddress:DWORD
	LOCAL 	thID:DWORD
	
	invoke 	CreateThread,0,0,pAddress,0,0,ADDR thID
	.if 	eax
		invoke 	CloseHandle,eax
	.endif
	ret

ThreadCall endp

Align 16

EnableInstCtl proc lState:DWORD
	
	invoke 	GetDlgItem,hInstallWnd,1003
	invoke 	EnableWindow,eax,lState
	invoke 	GetDlgItem,hInstallWnd,1004
	invoke 	EnableWindow,eax,lState
	ret

EnableInstCtl endp

Align 16

ShowInstP2 proc lState:DWORD
	
	invoke 	GetDlgItem,hInstallWnd,1009
	invoke 	ShowWindow,eax,lState
	ret

ShowInstP2 endp

Align 16

ShowInstP3 proc uses edi esi ebx lState:DWORD

	mov 	edi,GetDlgItem
	mov 	esi,ShowWindow
	mov 	ebx,hInstallWnd
	
	scall 	edi,ebx,1011
	scall 	esi,eax, lState
	scall 	edi,ebx,1012
	scall 	esi,eax, lState
	scall 	edi,ebx,1013
	scall 	esi,eax, lState
	scall 	edi,ebx,1014
	scall 	esi,eax, lState
	ret

ShowInstP3 endp

Align 16

ShowInstP4 proc uses edi esi ebx lState:DWORD

	mov 	edi,GetDlgItem
	mov 	esi,ShowWindow
	mov 	ebx,hInstallWnd
	
	scall 	edi,ebx,1015
	scall 	esi,eax, lState
	scall 	edi,ebx,1016
	scall 	esi,eax, lState
	scall 	edi,ebx,1017
	scall 	esi,eax, lState
	ret

ShowInstP4 endp

Align 16

ShowInstP5 proc uses edi esi ebx lState:DWORD

	mov 	edi,GetDlgItem
	mov 	esi,ShowWindow
	mov 	ebx,hInstallWnd
	
	scall 	edi,ebx,1018
	scall 	esi,eax, lState
	scall 	edi,ebx,1019
	scall 	esi,eax, lState
	scall 	edi,ebx,1020
	scall 	esi,eax, lState
	ret

ShowInstP5 endp

Align 16

InstallDlgProc proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	
	mov 	eax,uMsg
	.if 	eax == WM_INITDIALOG
		
		mov2 	hInstallWnd,hWin
		mov 	InstPos,0
		mov 	Selesai,0
		mov 	CreateShortcut,1
		mov 	NeedRestart,0
		
		mov esi,esi
		
		invoke 	SetWindowText,hWin,ADDR szInstallTitle
		invoke 	SendMessage,hWin,WM_SETICON,ICON_SMALL,hMainIcon
		
		cText 	a3,"Wisaya Pemasangan Ansav"
		cText 	a11,"Uninstall ANSAV" 
		.if 	Uninstall
			lea 	edx,a11
		.else
			lea 	edx,a3
		.endif
		invoke 	TxtColor,hWin,hInstance,edx,170,5,220,20,rgb(0,050h,200),0
		invoke 	ShowWindow,eax,SW_SHOW
		
		push 	ebx
		push 	esi
		mov 	ebx,GetDlgItem
		mov 	esi,ShowWindow
		scall 	ebx,hWin,1018
		mov 	hInstallPB,eax
		scall 	ebx,hInstallWnd,1007
		scall 	esi,eax,SW_HIDE
		scall 	ebx,hWin,1009
		mov 	hListInstall,eax
		invoke 	SendMessage,eax,LB_RESETCONTENT,0,0
		invoke 	ShowInstP2,FALSE
		scall 	ebx,hWin,1008
		scall 	esi,eax,SW_HIDE 
		scall 	ebx,hWin,1021
		scall 	esi,eax,SW_HIDE 
		scall 	ebx,hWin,1004
		invoke 	EnableWindow,eax,FALSE
		scall 	ebx,hWin,1002
		scall 	esi,eax,SW_SHOW
		pop 	esi
		pop 	ebx
		
		.if 	Uninstall
			invoke 	ShowInstP2,FALSE
			invoke 	ShowInstP3,FALSE
			invoke 	ShowInstP4,FALSE
			invoke 	ShowInstP5,FALSE
			push 	esi
			push 	ebx
			mov 	esi,GetDlgItem
			mov 	ebx,hWin
			
			invoke 	SetDlgItemText,ebx,1021,offset szUninstallMsg
			scall 	esi,ebx,1021
			invoke 	ShowWindow,eax,SW_SHOW
			scall 	esi,ebx,1002
			invoke 	ShowWindow,eax,SW_HIDE
			invoke 	SetDlgItemText,ebx,1003,reparg("Uninstall")
			pop		ebx
			pop 	esi
			mov 	InstPos,3
		.else
			invoke 	SetInstMsg,1002,ADDR szInsMsg01
			invoke 	ShowInstP3,FALSE
			invoke 	ShowInstP4,FALSE
			invoke 	ShowInstP5,FALSE
		.endif

IFDEF 	RELEASE
		.if 	!incmdl
			invoke	IsWindow,hConsoleLogDlg
			.if 	eax
				invoke 	ShowWindow,hConsoleLogDlg,SW_HIDE
			.endif
		.endif
ENDIF
		
	.elseif 	eax == WM_CLOSE
	@close:
		.if 	!Selesai
			.if 	Uninstall
				mov 	edx,reparg("Yakinkah Anda ingin membatalkan proses uninstall?")
			.else
				mov 	edx,reparg("Yakinkah Anda ingin mengakhiri wisaya pemasangan ANSAV?")
			.endif
			invoke 	MessageBox,hInstallWnd,edx,ADDR szInstallTitle,MB_OKCANCEL or MB_ICONQUESTION
			.if 	eax != IDOK
				xor 	eax,eax
				ret
			.endif
			invoke 	DestroyWindow,hWin
			.if 	!incmdl
				jmp 	@show
			.endif
		.else
			.if 	!NeedRestart && TestOkay && Selesai && !InstError
				invoke 	MessageBox,hInstallWnd,reparg("Jalankan ANSAV yang telah terpasang?"),ADDR szInstallTitle,MB_YESNO or MB_ICONQUESTION
				.if 	eax == IDYES
					
					lea 	esi,szInstallBuff
					invoke 	MyZeroMemory,esi,MAX_PATH
					invoke 	lstrcpy,esi,ADDR szInstallLocation
					lea 	eax,a10
					invoke 	lstrcat,esi,eax
					
					valloc 	sizeof PROCESS_INFORMATION
					mov 	ebx,eax
					valloc 	sizeof STARTUPINFO
					mov 	edi,eax
					.if 	ebx && edi
						
						mov 	[edi.STARTUPINFO].wShowWindow,1
						invoke 	CreateProcess,esi,0,0,0,0,0,0,ADDR szInstallLocation,edi,ebx
						
						vfree 	edi
						vfree 	ebx
						
					.endif
					
				.endif
				jmp 	GlobalExit
			.elseIF 	NeedRestart
				invoke 	ShowWindow,hInstallWnd,SW_HIDE
				call 	IsNT
				.if 	eax
					call 	SetShutdownTokenPrivilege
				.endif
				invoke 	ExitWindowsEx,EWX_REBOOT OR EWX_FORCE,0
				.if 	!eax
					invoke 	ExitWindowsEx,16,0
					.if 	!eax
						invoke 	ShowWindow,hInstallWnd,SW_SHOW
						invoke 	MessageBox,hInstallWnd,reparg("Gagal menghidupkan ulang komputer"),ADDR szInstallTitle,MB_OK
					.endif
				.endif
			.else
@show:
				mov 	InstalAbort,1
				.if 	!incmdl
					invoke 	ShowWindow,hMainWnd,SW_SHOW
				
IFDEF 	RELEASE
					invoke	IsWindow,hConsoleLogDlg
					.if 	eax
						invoke 	ShowWindow,hConsoleLogDlg,SW_SHOW
					.endif
ENDIF
				.endif
				.if 	Selesai
					invoke 	AppendLogConsole,reparg("Installation completed")
				.else
					invoke 	AppendLogConsole,reparg("Install/uninstall operation aborted")
				.endif
				invoke 	DestroyWindow,hWin
			.endif
		.endif
	.elseif 	eax == WM_COMMAND
		mov 	eax,wParam
		and 	eax,0FFFFh
		.if 	eax == 1005 	; <-- CLOSE ;
			jmp 	@close
		.elseif 	eax == 1004
			mov 	eax,InstPos
			dec 	InstPos
			.if 	eax == 1	; <-- BACK ;
				push 	ebx
				push 	esi
				mov 	esi,ShowWindow
				mov 	ebx,GetDlgItem
				scall 	ebx,hWin,1002
				scall 	esi,eax,SW_SHOW
				scall 	ebx,hWin,1009
				scall 	esi,eax,SW_HIDE
				scall 	ebx,hWin,1008
				scall 	esi,eax,SW_HIDE
				invoke 	ShowInstP3,FALSE
				invoke 	ShowInstP4,FALSE
				invoke 	ShowInstP5,FALSE
				scall 	ebx,hWin,1004
				pop 	esi
				pop 	ebx
				invoke 	EnableWindow,eax,FALSE
				cText 	szLanjut,"Lanjut"
				invoke 	SetDlgItemText,hInstallWnd,1003,offset szLanjut 
			.elseif 	eax == 2
				invoke 	ShowInstP2,TRUE
				invoke 	ShowInstP3,FALSE
				invoke 	ShowInstP4,FALSE
				invoke 	ShowInstP5,FALSE
				cText	a4,"Test kompatibilitas"
				invoke 	SetDlgItemText,hWin,1008,offset a4
			.elseif 	eax == 3
				invoke 	ShowInstP2,FALSE
				invoke 	ShowInstP3,TRUE
				invoke 	ShowInstP4,FALSE
				invoke 	ShowInstP5,FALSE
				cText 	a5,"Pilih lokasi"
				cText 	a7,"Pasang"
				invoke 	SetDlgItemText,hInstallWnd,1003,offset szLanjut
				invoke 	SetDlgItemText,hWin,1008,offset a5
			.elseif 	eax == 4
				invoke 	ShowInstP2,FALSE
				invoke 	ShowInstP3,FALSE
				invoke 	ShowInstP4,TRUE
				invoke 	ShowInstP5,FALSE
				invoke 	SetDlgItemText,hInstallWnd,1003,offset a7
				cText 	a6,"Opsional"
				invoke 	SetDlgItemText,hWin,1008,offset a6
				invoke 	CheckDlgButton,hWin,1015,BST_CHECKED
			.endif
		.elseif 	eax == 1003	; <-- NEXT ;
			mov 	eax,InstPos
			.if 	eax == 0
				push 	esi
				mov 	esi,GetDlgItem
				invoke 	SendMessage,hListInstall,LB_RESETCONTENT,0,0
				scall 	esi,hWin,1002
				invoke 	ShowWindow,eax,SW_HIDE
				scall 	esi,hWin,1009
				invoke 	ShowWindow,eax,SW_SHOW
				invoke 	SetDlgItemText,hWin,1008,offset a4
				scall 	esi,hWin,1008
				invoke 	ShowWindow,eax,SW_SHOW
				invoke 	EnableInstCtl,FALSE
				invoke 	ShowInstP3,FALSE
				scall 	esi,hWin,1004
				pop 	esi
				invoke 	EnableWindow,eax,FALSE
				;-------------------------------------- PEMERIKSAAN KOMPATIBILITAS ----------------------------------------;
				
				mov 	TestOkay,0
				mov 	InstalAbort,0
				mov 	InTest,1
				lea 	eax,CompatibilityCheck
				invoke 	ThreadCall,eax
				
				
			.elseif 	eax==1
				
				.if 	TestOkay
					; ------- Pilih lokasi ------- ;
					invoke 	ShowInstP2,FALSE
					invoke 	ShowInstP3,TRUE
					invoke 	ShowInstP4,FALSE
					invoke 	ShowInstP5,FALSE
					invoke 	GetDlgItem,hWin,1008
					invoke 	ShowWindow,eax,SW_SHOW
					
					invoke 	SetDlgItemText,hWin,1008,offset a5
					
				.else
					; ------- details kegagalan ------- ;
					scall 	BuildForFailedStub,FailedStub
					invoke 	SetDlgItemText,hWin,1008,reparg("Detail kegagalan, dan pemecahannya")
					invoke 	GetDlgItem,hWin,1009
					invoke 	ShowWindow,eax,SW_HIDE
					invoke 	GetDlgItem,hWin,1002
					invoke 	ShowWindow,eax,SW_SHOW
					invoke 	EnableInstCtl,FALSE
					invoke 	SetDlgItemText,hWin,1005,reparg("OK")
				.endif
				
			.elseif 	eax == 2 ; ------- PILIH LOKASI!! ------- ;
				lea 	eax,szInstallLocation
				mov 	byte ptr [eax],0
				invoke 	GetDlgItemText,hInstallWnd,1011,eax,1024
				lea 	eax,szInstallLocation
				
				.if 	byte ptr [eax]==0
					invoke 	MessageBox,hInstallWnd,reparg("Pilih terlebih dahulu tempat pemasangan ANSAV."),ADDR szInstallTitle,MB_OK
					ret 
				.endif
				invoke	GetFileAttributes,ADDR szInstallLocation
				mov 	ebx,eax
				invoke 	GetLastError
				.if 	eax == ERROR_FILE_NOT_FOUND || eax == ERROR_PATH_NOT_FOUND
					lea 	eax,szInstallLocation
					cmp 	byte ptr [eax+1],':'
					.if 	!zero?
						invoke 	MessageBox,hInstallWnd,reparg("Alamat tidak valid. ANSAV juga tidak mendukung installasi melalui jaringan. Pilih alamat lain."),ADDR szInstallTitle,MB_OK
						ret  
					.else
						invoke 	MessageBox,hInstallWnd,reparg("Lokasi yang anda pilih belum ada, ijinkan ANSAV membuat direktori baru?."),ADDR szInstallTitle,MB_YESNO or MB_ICONQUESTION
						.if 	eax == IDNO
							ret
						.endif
					.endif
				.endif
				invoke 	ShowInstP2,FALSE
				invoke 	ShowInstP3,FALSE
				invoke 	ShowInstP4,TRUE
				invoke 	ShowInstP5,FALSE
				invoke 	SetDlgItemText,hInstallWnd,1003,offset a7
				invoke 	SetDlgItemText,hWin,1008,offset a6
				invoke 	CheckDlgButton,hWin,1015,BST_CHECKED
				
			.elseif 	eax == 3 ; ------- INSTALL!! ------- ; 
				invoke 	ShowInstP2,FALSE
				invoke 	ShowInstP3,FALSE
				invoke 	ShowInstP4,FALSE
				invoke 	ShowInstP5,TRUE
				invoke 	EnableInstCtl,FALSE
				;call 	Pasang
				invoke 	SendMessage,hInstallPB,PBM_SETRANGE32,0,100
				
				.if 	Uninstall
					invoke 	GetDlgItem,hInstallWnd,1019
					invoke 	ShowWindow,eax,SW_SHOW
					call 	StartUninstallANSAV
				.else
					push 	esi
					lea 	esi,szInstallLocation
					invoke 	TruePath,esi
					invoke 	lstrcat,esi,ADDR szAnsavName
					pop 	esi
					call	StartPasang
				.endif
			.endif
			inc 	InstPos
		.elseif 	eax == 1012	; <-- BROWSE ;
			invoke 	BrowseForFolder,hInstallWnd,ADDR szInstallBuff,ADDR szInstallTitle,reparg("Pilih tempat pemasangan ANSAV"),1
			.if 	eax
				.if 	szInstallBuff[0]
					invoke 	SetDlgItemText,hInstallWnd,1011,ADDR szInstallBuff
				.endif
			.endif
		.elseif 	eax == 1015 	; <-- BUAT PINTASAN ;
			invoke 	IsDlgButtonChecked,hWin,1015
			mov 	CreateShortcut,eax
		.elseif 	eax == 1016
			invoke 	IsDlgButtonChecked,hWin,1016
			mov 	NeedRestart,eax
		.endif
		
	.endif
	
	
	xor 	eax,eax
	ret
	
InstallDlgProc endp


	align 16

CompatibilityCheck proc ;------------------------------------------------------------------------------;

	; ------- seh installation ------- ;
	SehBegin 	_sub_cc

	mov 	FailedStub,0
	mov 	lpszFailedBuff,0
	
	.if 	InstalAbort
		invoke 	ExitThread,0
	.endif
	invoke 	IsNT
	.if 	eax
		; ------- Check Administrator Right ------- ;
		invoke 	AddInstMsg,ADDR szSeparator2,0
		invoke 	AddInstMsg,reparg("# Check Administrator Right..."),500
		invoke 	IsAdmin
		.if 	!eax
			mov 	FailedStub,1
			invoke 	SubInstMsg,ADDR szGagal
			invoke 	AddInstMsg,reparg("Anda tidak memiliki hak akses Administrator"),0
			invoke 	AddInstMsg,reparg("pastikan Anda memiliki hak akses administrator"),0
			invoke 	AddInstMsg,reparg("untuk memasang ANSAV, coba jalankan ANSAV dari"),0
			invoke 	AddInstMsg,reparg("context menu Run As..."),0
			jmp 	@failed 
		.endif
		
		invoke 	SubInstMsg,ADDR szOk
		
	.endif
	.if 	InstalAbort
		invoke 	ExitThread,0
	.endif
	
	; ------- Check file windows net.exe/regsvr.exe dll ------- ;
	invoke 	AddInstMsg,ADDR szSeparator2,0
	invoke 	AddInstMsg,reparg("# Check komponen eksternal..."),500
	
		; ------- NET.EXE ------- ;
		invoke 	AddInstMsg,reparg("  o SCM Controler "),500
		invoke	lstrcpy,ADDR szInstallBuff,ADDR szWinDir
		invoke 	TruePath,ADDR szInstallBuff
		invoke 	lstrcat,ADDR szInstallBuff,reparg("NET.exe")
		invoke 	FileExist,ADDR szInstallBuff
		test 	eax,eax
		jnz 	@scmok	
		
		lea 	edi,szInstallBuff
		invoke	lstrcpy,edi,ADDR szSysDir
		invoke 	TruePath,edi
		invoke 	lstrcat,edi,reparg("NET.exe")
		invoke 	FileExist,edi
		.if 	!eax	
			invoke 	SubInstMsg,ADDR szGagal
			
			; check what?
			valloc 	1024
			.if 	eax
				mov 	lpszFailedBuff,eax
				lea 	esi,szInstallBuff2
				invoke 	MyZeroMemory,esi,MAX_PATH
				invoke 	QGetFileSize,edi
				invoke 	wsprintf,esi,reparg("nt=%ph"),eax
				invoke 	lstrcpy,lpszFailedBuff,esi
			.endif
			
			jmp 	@failed2
		.endif 	
@scmok:
		invoke 	SubInstMsg,ADDR szOk
		.if 	InstalAbort
			invoke 	ExitThread,0
		.endif
		; ------- CMD.exe ------- ;
		invoke 	AddInstMsg,reparg("  o Console System "),500
		lea 	edi,szInstallBuff
		invoke 	MyZeroMemory,edi,MAX_PATH
		invoke	lstrcpy,edi,ADDR szSysDir
		invoke 	TruePath,edi
		invoke 	lstrcat,edi,reparg("cmd.exe")
		invoke 	FileExist,edi
		.if 	!eax
			invoke 	SubInstMsg,ADDR szGagal
			
			.if 	!lpszFailedBuff
				; check what?
				valloc 	1024
				.if 	eax
					mov 	lpszFailedBuff,eax
					lea 	esi,szInstallBuff2
					invoke 	MyZeroMemory,esi,MAX_PATH
					invoke 	QGetFileSize,edi
					invoke 	wsprintf,esi,reparg("cd=%ph"),eax
					invoke 	lstrcpy,lpszFailedBuff,esi
				.endif
			.endif
			
			jmp 	@failed2
		.endif
		invoke 	SubInstMsg,ADDR szOk
		.if 	InstalAbort
			invoke 	ExitThread,0
		.endif
		
		; ------- Service.exe ------- ;
		invoke 	AddInstMsg,reparg("  o Service Management "),500
		
		invoke 	SubInstMsg,ADDR szOk
		.if 	InstalAbort
			invoke 	ExitThread,0
		.endif
		; ------- CHECK KOMPONEN INTERNAL an32hk.dll,dll.. ------- ;
		invoke 	AddInstMsg,ADDR szSeparator2,0
		invoke 	AddInstMsg,reparg("# Check komponen internal..."),500
		
		invoke 	AddInstMsg,reparg("  o anPdetector.dll "),500
		lea 	edi,szInstallBuff
		invoke 	lstrcpy,edi,ADDR szMyDir
		invoke 	TruePath,edi
		invoke 	lstrcat,edi,ADDR szanPdetectordll	; <-- anpdetector.dll ;
		; #1
		invoke 	FileExist,edi
		.if 	!eax
			@@:
			invoke 	SubInstMsg,ADDR szGagal
			jmp 	@failed3
		.endif
		; #2 validator
		invoke 	LoadLibrary,edi
		.if 	!eax
			jmp 	@B
		.endif
		mov 	ebx,eax
		mov 	esi,GetProcAddress
		scall 	esi,ebx,offset szWhatThePackerEx
		.if 	!eax
			jmp 	@B
		.endif
		scall 	esi,ebx,offset szPackerType2String
		.if 	!eax
			jmp 	@B
		.endif
		mov 	eax,reparg("GetPdbCount")
		scall 	esi,ebx,eax
		.if 	!eax
			jmp 	@B
		.endif
		mov 	eax,reparg("DllGetVersion")
		scall 	esi,ebx,eax
		.if 	!eax
			jmp 	@B
		.endif
		
		invoke 	LoadLibrary,ADDR szInstallBuff
		.if 	!eax
			invoke 	SubInstMsg,ADDR szGagal
			jmp 	@failed3
		.endif
		mov 	ebx,eax
		invoke 	GetProcAddress,ebx,ADDR szWhatThePackerEx
		.if 	!eax
			invoke 	SubInstMsg,ADDR szGagal
			jmp 	@failed3
		.endif
		invoke 	GetProcAddress,ebx,ADDR szPackerType2String
		.if 	!eax
			invoke 	SubInstMsg,ADDR szGagal
			jmp 	@failed3
		.endif
		
		invoke 	SubInstMsg,ADDR szOk
		.if 	InstalAbort
			invoke 	ExitThread,0
		.endif
		invoke 	AddInstMsg,reparg("  o an32hk.dll "),500	; <-- an32hk.dll ;
		invoke 	lstrcpy,ADDR szInstallBuff,ADDR szMyDir
		invoke 	TruePath,ADDR szInstallBuff
		invoke 	lstrcat,ADDR szInstallBuff,ADDR szAnhookerDll
		; #1
		invoke 	FileExist,ADDR szInstallBuff
		.if 	!eax
			invoke 	SubInstMsg,ADDR szGagal
			jmp 	@failed3
		.endif
		; #2 CHECK VALIDATOR
		invoke 	LoadLibrary,ADDR szAnhookerDll
		.if 	!eax
			invoke 	SubInstMsg,ADDR szGagal
			jmp 	@failed3
		.endif
		mov 	ebx,eax
		invoke 	GetProcAddress,ebx,ADDR szInstallHook
		.if 	!eax
			invoke 	SubInstMsg,ADDR szGagal
			jmp 	@failed3
		.endif
		invoke 	GetProcAddress,ebx,ADDR szUninstallHook
		.if 	!eax
			invoke 	SubInstMsg,ADDR szGagal
			jmp 	@failed3
		.endif
		invoke 	GetProcAddress,ebx,ADDR sz__dhm
		.if 	!eax
			invoke 	SubInstMsg,ADDR szGagal
			jmp 	@failed3
		.endif
		call 	eax	; <-- don't hook self ;
		invoke 	GetProcAddress,ebx,ADDR sz__ghpd
		.if 	!eax
			invoke 	SubInstMsg,ADDR szGagal
			jmp 	@failed3
		.endif
		invoke 	GetProcAddress,ebx,ADDR sz__isao32
		.if 	!eax
			invoke 	SubInstMsg,ADDR szGagal
			jmp 	@failed3
		.endif
		mov 	_IsCanHook?,eax	; <-- save for future use ;
		; #5 FINAL
		invoke 	SubInstMsg,ADDR szOk
		.if 	InstalAbort
			invoke 	ExitThread,0
		.endif
		
		; ste.dll
		invoke 	AddInstMsg,reparg("  o ste.dll "),500	; <-- ste.dll ;
		lea 	edi,szInstallBuff
		invoke 	lstrcpy,edi,offset szMyDir
		invoke 	TruePath,edi
		invoke 	lstrcat,edi,offset szSteDll
		; #1
		invoke 	FileExist,edi
		.if 	!eax
			invoke 	SubInstMsg,ADDR szGagal
			jmp 	@failed3
		.endif
		invoke 	SubInstMsg,ADDR szOk
		
		.if 	InstalAbort
			invoke 	ExitThread,0
		.endif
		
		; agd32.sys
		invoke 	AddInstMsg,reparg("  o agd32.sys "),500	; <-- agd32.sys ;
		invoke 	lstrcpy,edi,offset szMyDir
		invoke 	TruePath,edi
		invoke 	lstrcat,edi,offset szAgd32sys
		; #1
		invoke 	FileExist,edi
		.if 	!eax
			invoke 	SubInstMsg,ADDR szGagal
			jmp 	@failed3
		.endif
		invoke 	SubInstMsg,ADDR szOk
		
		; ------- CHECK REGISTRY INTEGRITY ------- ;
		invoke 	AddInstMsg,ADDR szSeparator2,0
		invoke 	AddInstMsg,reparg("# Check Registry entry..."),500
		invoke	SetRegString,HKEY_LOCAL_MACHINE,reparg("SAM\"),reparg("regcheck"),reparg("check")
		.if 	eax
			invoke 	SubInstMsg,ADDR szGagal
			jmp 	@failed4
		.endif
		
		invoke 	SubInstMsg,ADDR szOk
		invoke 	DeleteKeyValue,HKEY_LOCAL_MACHINE,reparg("SAM\"),reparg("regcheck")
		.if 	InstalAbort
			invoke 	ExitThread,0
		.endif
		invoke 	AddInstMsg,ADDR szSeparator2,0
		invoke 	AddInstMsg,reparg("# Test Syncro Object..."),500
		invoke 	CreateMutex,0,0,reparg("__protected__")
		mov 	ebx,eax
		invoke 	GetLastError
		.if 	eax
			invoke 	SubInstMsg,ADDR szGagal
			jmp 	@failed5
		.endif
		invoke 	CloseHandle,ebx
		invoke 	SubInstMsg,ADDR szOk
		.if 	InstalAbort
			invoke 	ExitThread,0
		.endif
		
		.if 	InstalAbort
			invoke 	ExitThread,0
		.endif
		invoke 	AddInstMsg,ADDR szSeparator2,0
		invoke 	AddInstMsg,reparg("# Check Native API..."),500
		
		; ------- native API stub check ------- ;
		mov 	lpszFailedBuff,0
		call 	_IsCanHook?
		.if 	!eax
			
			; ------- check what the pk! ------- ;
			valloc 	1024*4
			.if 	eax
				mov 	lpszFailedBuff,eax
				
				;-------------------------------------- START DUMPING ----------------------------------------;
				szText 	szGetCurrentDirectoryW,"GetCurrentDirectoryW"
				szText 	szCreateProcessInternalW,"CreateProcessInternalW"
				invoke 	GetModuleHandle,reparg("kernel32.dll")
				.if 	eax
					mov 	ebx,eax
					mov 	esi,lpszFailedBuff
					
					jmp 	@F
							er01 db "RVA Dump on kernel32!GCDW",13,10
								 db "0x29 bytes size",13,10,0
							er02 db 13,10,13,10,"RVA Dump on kernel32!CPIW",13,10
								 db "0x35 bytes size",13,10,0
					@@:
					invoke 	lstrcpy,esi,offset er01

					strlen esi
					
					add 	esi,eax
					invoke 	GetProcAddress,ebx,ADDR szGetCurrentDirectoryW
					.if 	eax
						invoke 	HexDump,eax,029h,esi
					.endif
					
					invoke 	lstrcat,esi,offset er02
					
					strlen esi
					
					add 	esi,eax
					invoke 	GetProcAddress,ebx,ADDR szCreateProcessInternalW
					.if 	eax
						invoke 	HexDump,eax,035h,esi
					.endif
				.endif
				
			.endif
			
			invoke 	SubInstMsg,ADDR szGagal
			jmp 	@failed6
		.endif
		invoke 	SubInstMsg,ADDR szOk
		
		align 8
		
		; ------- TAHAP TEST SELESAI ------- ;
		invoke 	AddInstMsg,ADDR szSeparator2,0
		invoke 	AddInstMsg,reparg("Test selesai..., proses pemasangan siap dilanjutkan."),0
		cText	a1,'Klik "Lanjut" untuk meneruskannya, '
		invoke 	AddInstMsg,offset a1,0
		cText 	a2,'sebaliknya klik "Batal" untuk mengakhirinya.'
		invoke 	AddInstMsg,offset a2,0
		invoke 	AddInstMsg,ADDR szKosong,0
		invoke 	SetDlgItemText,hInstallWnd,1003,offset szLanjut
		invoke 	EnableInstCtl,TRUE
		mov 	TestOkay,1
		mov 	InTest,0
		invoke 	ExitThread,0
		
		; ------- seh trapper ------- ;
		SehTrap 	_sub_cc
			ErrorDump 	"Sub CompatibilityCheck",offset CompatibilityCheck,"Install.asm"
		SehEnd 		_sub_cc
		
	ret

@failed6:
	mov 	FailedStub,6
	invoke 	AddInstMsg,reparg("    Beberapa perintah native API tidak kompatibel"),0
	invoke 	AddInstMsg,reparg("    dengan komponen ANSAV."),0
	invoke 	AddInstMsg,reparg("    Laporkan hal ini kepada author"),0
	invoke 	AddInstMsg,reparg("    untuk keperluan pengembangan."),0
	jmp 	@failed	
@failed5:
	mov 	FailedStub,5
	invoke 	AddInstMsg,reparg("    Tidak dapat melakukan syncro object test. "),0
	invoke 	AddInstMsg,reparg("    Suatu hal yang aneh.., laporkan ini pada"),0
	invoke 	AddInstMsg,reparg("    ansav support."),0
	jmp 	@failed
@failed4:
	mov 	FailedStub,4
	invoke 	AddInstMsg,reparg("    Registry tidak dapat diakses, mungkin rusak "),0
	invoke 	AddInstMsg,reparg("    atau corrupt."),0
	jmp 	@failed
@failed3:
	mov 	FailedStub,3
	invoke 	AddInstMsg,reparg("     beberapa komponen internal tidak tersedia"),0
	invoke 	AddInstMsg,reparg("     kemungkinan rusak atau tidak ada."),0
	invoke 	AddInstMsg,reparg("     coba download ulang ANSAV  lengkap beserta"),0
	invoke 	AddInstMsg,reparg("     komponen-komponennya."),0
	invoke 	AddInstMsg,reparg("     download di http://www.ansav.com."),0
	jmp 	@failed
@failed2:
	mov 	FailedStub,2
	invoke 	AddInstMsg,reparg("     beberapa komponen eksternal tidak tersedia"),0
	invoke 	AddInstMsg,reparg("     kemungkinan rusak atau tidak ada."),0
@failed:
	invoke 	AddInstMsg,ADDR szSeparator2,0
	invoke 	AddInstMsg,reparg("Proses pemasangan gagal"),0
	invoke 	AddInstMsg,reparg("Info lebih lanjut klik detail"),0
	invoke 	AddInstMsg,ADDR szKosong,0
	invoke 	SetDlgItemText,hInstallWnd,1003,reparg("Detail")
	invoke 	GetDlgItem,hInstallWnd,1004
	invoke 	EnableInstCtl,TRUE
	invoke 	EnableWindow,eax,FALSE
	mov 	InTest,0
	mov 	Selesai,1
	SehPop
	retn

CompatibilityCheck endp

;------------------------------------------------------------------------------;
Align 16
.data
	szFStubMsg01 	db "Kegagalan terletak pada hak akses yang Anda miliki. "
					db "ANSAV Guard membutuhkan hak akses administrator untuk "
					db "beroperasi. Karena demi keamanan yang ketat "
					db "ANSAV Guard harus dipasang sebagai "
					db "System Service Authority.",13,10,13,10
					db "Untuk memecahkan masalah ini. Jika Anda adalah seorang "
					db "Administrator yang berhak atas komputer ini, jalankan "
					db 'ANSAV dengan menggunakan "Run As.." (super usernya Windows), '
					db "Dan masukkanlah akun administrator Anda.",13,10,13,10,0 
	
	szFStubMsg02	db "Beberapa komponen eksternal yang dibutuhkan ANSAV Guard untuk "
					db "proses pemasangan tidak tersedia, sehingga proses pemasangan "
					db "tidak bisa berjalan dengan baik. "
					db "Kemungkinan memang komponen tidak ada, atau bisa juga karena " 
					db "ANSAV Guard belum bisa menghandle-nya yang disebabkan kompatibilitas.",13,10,13,10
					db "Untuk memecahkan masalah ini. Kirimkan informasi teknis berikut "
					db "kepada pembuat ANSAV sebagai bahan acuan dalam pengembangan selanjutnya :",13,10,13,10
					db "%s",13,10,13,10,0
	
	szFStubMsg03 	db "Kegagalan terletak pada ketidaklengkapan komponen ANSAV. "
					db 'seperti, file pendukung "anPdetector.dll" dan "an32hk.dll" '
					db "karena file tersebut berguna untuk memberikan keamanan ekstra " 
					db "pada komputer anda ketika Anda sedang bekerja.",13,10,13,10
					db "Untuk memecahkan masalah ini. Anda harus memiliki ANSAV "
					db "lengkap beserta komponen-komponennya. Caranya, download "
					db "ANSAV terbaru dari situs yang dapat dipercaya, dan pastikan "
					db "terdapat file-file pendukung seperti yang telah disebutkan "
					db "diatas.",13,10,13,10
					db "Alamat website resmi ANSAV : http://www.ansav.com",0 

	szFStubMsg04 	db "Kegagalan terletak pada akses registry pada komputer Anda, "
					db "ANSAV Guard tidak dapat mengakses Registry Anda, yang mungkin "
					db "disebabkan karena beberapa informasi Regitry tidak ada, rusak, atau "
					db "corrupt.",13,10,13,10
					db "Untuk memecahkan masalah ini. Coba gunakan utility khusus "
					db 'yang bisa digunakan untuk memperbaiki registry, seperti "registry recovery" dll.',13,10,13,10,0
					
	szFStubMsg05	db "Kegagalan terletak pada waktu ANSAV melakukan test sinkronasi. "
					db "Test sinkronasi ini penting untuk menjaga kestabilann. "
					db "Hal ini kemungkinan disebabkan karena anda memiliki "
					db "lebih dari 1 Antivirus terpasang, termasuk juga ANSAV +E yang lama. ",13,10,13,10
					db "Untuk memecahkan masalah ini. Jika Anda memiliki ANSAV +E yang lama "
					db "dan sedang berjalan di memory, hentikan terlebih dahulu. Jika Anda "
					db "memiliki Antivirus lain yang terpasang, coba uninstall terlebih dahulu, kemudian " 
					db "jalankan kembali instalasi.",13,10,13,10,0

	szFStubMsg06	db "Kegagalan terletak pada ketidakcocokan perintah native API "
					db "yang ada pada sistem operasi Anda dengan komponen ANSAV. "
					db "Tidak ada pemecahan masalah yang bisa diberikan disini, "
					db "hal ini dikarenakan merupakan permasalahan internal "
					db "yang terdapat pada ANSAV, atau sebuah bug kompatibilitas. ",13,10
					db "Untuk pengembangan ANSAV agar bisa mendukung dengan "
					db "sistem yang Anda gunakan, Kirimkan informasi teknis berikut "
					db "kepada pembuat ANSAV : ",13,10,13,10
					db "%s",13,10,13,10
					db "contact : anvie_2194@yahoo.com",13,10
					db "Alamat website resmi ANSAV : http://www.ansav.com",0 
.code

BuildForFailedStub proc uses esi fstub:DWORD

	invoke 	MyZeroMemory,ADDR szInstallBuff,1024
	
	mov 	eax, fstub
	.if 		eax == 1	; <-- ADMINISTRATOR RIGHT ;
		invoke 	SetDlgItemText,hInstallWnd,1002,ADDR szFStubMsg01
	.elseif 	eax == 2	; <-- beberapa komponen eksternal tidak tersedia ;
		.if 	lpszFailedBuff
			
			valloc 	1024*2
			.if 	eax
				mov 	esi,eax
				
				invoke 	wsprintf,esi,offset szFStubMsg02,lpszFailedBuff
				invoke 	SetDlgItemText,hInstallWnd,1002,esi
				
				vfree 	esi
			.else
				call 	@galokasi
			.endif
			
			vfree 	lpszFailedBuff
		.else
			call 	@galokasi
		.endif
	.elseif 	eax == 3	; <-- beberapa komponen internal tidak tersedia ;
		invoke 	SetDlgItemText,hInstallWnd,1002,ADDR szFStubMsg03
	.elseif 	eax == 4	; <-- Registry tidak dapat diakses, mungkin rusak ;
		invoke 	SetDlgItemText,hInstallWnd,1002,ADDR szFStubMsg04
	.elseif 	eax == 5	; <-- Tidak dapat melakukan syncro object test. ;
		invoke 	SetDlgItemText,hInstallWnd,1002,ADDR szFStubMsg05
	.elseif 	eax == 6 	; <-- Beberapa perintah native API tidak kompatibel ;
		.if 	lpszFailedBuff
			valloc 	1024*4
			.if 	eax
				mov 	esi,eax
				
				push 	lpszFailedBuff
				push 	offset szFStubMsg06
				push 	esi
				call 	wsprintf
				invoke 	SetDlgItemText,hInstallWnd,1002,esi
				

				vfree	esi
			.else
				call 	@galokasi
			.endif
			vfree 	lpszFailedBuff
		.else
			call 	@galokasi
		.endif
	.endif
	
	ret
@galokasi:
	invoke 	SetDlgItemText,hInstallWnd,1002,reparg("Gagal mengalokasikan 1024*4 bytes virtual memory untuk menggenerasikan sebab kesalahan.")
	retn
BuildForFailedStub endp

Align 16

StartInstallDlgProc proc
	
	
	invoke 	IsAlreadyInstalled?
	.if 	eax
		invoke 	MessageBox,0,reparg("ANSAV already installed on your computer. Installation aborted."),ADDR szAppName,MB_OK
		ret
	.endif
	
	.if 	!incmdl
		invoke 	AppendLogConsole,reparg("Preparing Installation....")
	.endif
	xor 	eax,eax
	.if 	!incmdl
		mov 	eax,hMainWnd
		lea 	ecx,szAppName
		mov 	edx,reparg("This will Install ANSAV on your computer. All last scanned infromation will be lost, are You ready?")
	.else
		mov 	edx,reparg("This will Install ANSAV on your computer. Are You ready?")
		lea	 	ecx,szInstallTitle
	.endif
	invoke 	MessageBox,eax,edx,ecx,MB_OKCANCEL or MB_ICONQUESTION
	.if 	eax == IDOK

		.if 	incmdl
			invoke 	DialogBoxParam,hInstance,IDD_INSTALL,0,ADDR InstallDlgProc,0
		.else
IFDEF 	RELEASE
			invoke 	ShowWindow,hMainWnd,SW_HIDE
ENDIF
			invoke 	CreateDialogParam,hInstance,IDD_INSTALL,0,ADDR InstallDlgProc,0
		.endif
		
	.endif
	
	ret

StartInstallDlgProc endp

Align 16


InstallUninstallAnsav proc
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	
	invoke 	MyZeroMemory,ADDR lBuff,MAX_PATH
	call 	IsAlreadyInstalled?
	.if 	!eax
		; ------- INSTALL ------- ;
		mov 	Uninstall,0
		call 	StartInstallDlgProc
	.else
		; ------- UNINSTALL ------- ;
		invoke 	MessageBox,hMainWnd,reparg("This will uninstall ANSAV from your computer. Are you sure to uninstall ANSAV?"),ADDR szAppName,MB_OKCANCEL or MB_ICONQUESTION
		.if 	eax == IDOK
			mov 	Uninstall,1	
			call 	IsAdmin
			.if 	eax
IFDEF 	RELEASE
				invoke 	ShowWindow,hMainWnd,SW_HIDE
ENDIF
				invoke 	CreateDialogParam,hInstance,IDD_INSTALL,0,offset InstallDlgProc,0
			.else
				invoke 	MessageBox,hInstallWnd,reparg("You need administrator right to perform this action."),ADDR szAppName,MB_OK
			.endif
		.endif 
	.endif
	
	ret

InstallUninstallAnsav endp

Align 16

InstListCount proc
	
	invoke 	SendMessage,hListInstall,LB_GETCOUNT,0,0
	dec 	eax
	ret

InstListCount endp

Align 16

InstallStatus proc lpStatus:DWORD
	
	invoke 	GetDlgItem,hInstallWnd,1020
	invoke 	SetWindowText,eax,lpStatus
	invoke 	Sleep,1500
	
	ret

InstallStatus endp

Align 16

InstallRange proc r:DWORD
	
	invoke 	SendMessage,hInstallPB,PBM_SETPOS,r,0
	invoke 	Sleep,50
	ret

InstallRange endp

Align 16

include 	inc/service.asm

ALign 16

include 	inc/Shortcut.asm

Align 16

Pasang proc uses edi esi ebx lParam:DWORD
	
	;-------------------------------------- INSTALLATION PROGRESS ----------------------------------------;
	
	LOCAL 	lBuff[MAX_PATH+1]:BYTE
	LOCAL 	hInstPB,hTxtStatus,hRsrc,hRsrcSize:DWORD
	LOCAL 	hFile,fSize,memptr:DWORD
	LOCAL 	tmp,tmp2,hFind:DWORD
	LOCAL 	wfd:WIN32_FIND_DATA
	
	; ------- seh installation ------- ;
	SehBegin	__p
	
	mov 	Selesai,0
	mov 	RoolBack,0
	mov 	FailedStub,6
	mov 	InstError,0
	
	invoke 	InstallRange,0
	invoke	GetDlgItem,hInstallWnd,1018
	mov 	hInstPB,eax
	invoke	GetDlgItem,hInstallWnd,1020
	mov 	hTxtStatus,eax
	
	invoke 	SetDlgItemText,hInstallWnd,1008,reparg("Pemasangan, silahkan tunggu...")
	
	; ------- init ------- ;
	invoke 	InstallStatus,reparg("Initializing...")
	mov 	ebx,TruePath
	scall 	ebx,offset szMyDir
	scall 	ebx,offset szInstallLocation
	scall 	ebx,offset szSysDir
	scall 	ebx,offset szWinDir
	
	invoke 	InstallRange,5
	
	; ------- Build Directory + sub directory ------- ;
	invoke 	BuildDirectoryFromPath,offset szInstallLocation
	scall 	ebx,offset szInstallLocation
	
	invoke 	InstallRange,10
	; ------- kopikan ansavgd.exe ke direktori Windows ------- ;
	invoke 	InstallStatus,reparg("Copying files...")
	lea 	edi,lBuff
	invoke 	MyZeroMemory,edi,MAX_PATH
	invoke 	lstrcpy,edi,ADDR szMyDir
	invoke 	lstrcat,edi,ADDR szAgd32sys
	
	; fix subsytem
	invoke 	InstallRange,15
	invoke 	CreateFile,edi,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	.if 	eax==-1
		@bx:
		ViewError 	hInstallWnd,offset szGagalExtractAgd
		jmp 	@failed
	.endif
	mov 	hFile,eax
	invoke 	GetFileSize,eax,0
	.if 	!eax
IFDEF 	DEBUG
		invoke 	AppendLogConsole,reparg("invoke 	GetFileSize,eax,0")
ENDIF
		jmp 	@bx
	.endif
	mov 	fSize,eax
	valloc 	eax
	.if 	!eax
		invoke 	CloseHandle,hFile
		ViewError 	hInstallWnd,"Gagal mengalokasikan memory."
		jmp 	@failed
	.endif
	
	mov 	memptr,eax
	
	invoke 	ReadFile,hFile,memptr,fSize,ADDR brw,0
	invoke 	CloseHandle,hFile
	
	mov 	esi,memptr
	add 	si,03ch
	add 	si,[esi]
	sub 	si,03ch
	mov 	ax,[esi.IMAGE_NT_HEADERS].FileHeader.Characteristics ;,01000h
	test 	ax,1000h 
	.if 	!zero?
		xor 	[esi.IMAGE_NT_HEADERS].FileHeader.Characteristics,1000h
	.endif
	lea 	edi,lBuff
	invoke 	MyZeroMemory,edi,MAX_PATH
	invoke 	lstrcpy,edi,ADDR szWinDir
	cText 	szAnsavGdExe,"ansavgd.exe"
	invoke 	lstrcat,edi,ADDR szAnsavGdExe
	invoke 	FileExist,edi
	.if 	eax
		invoke 	SetFileAttributes,edi,FILE_ATTRIBUTE_NORMAL
		invoke 	DeleteFile,edi
	.endif
	invoke 	CreateFile,edi,GENERIC_WRITE,FILE_SHARE_WRITE,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0
	.if 	eax==-1
		vfree 	memptr
		jmp 	@bx
	.endif
	mov 	hFile,eax
	invoke 	SetFilePointer,eax,0,0,FILE_BEGIN
	invoke 	WriteFile,hFile,memptr,fSize,ADDR brw,0
	.if 	!eax
		vfree 	memptr
		jmp 	@bx
	.endif
	invoke 	CloseHandle,hFile
	vfree 	memptr
	
	inc 	RoolBack	; <-- set ;
	
	invoke 	InstallRange,20
	; ------- kopikan komponen hooker dan pdetector.dll ------- ;
	; #1 anhooker
	lea 	edi,lBuff
	invoke 	MyZeroMemory,edi,MAX_PATH
	lea 	esi,szInstallBuff
	invoke 	MyZeroMemory,esi,MAX_PATH
	invoke 	lstrcpy,esi,ADDR szMyDir
	invoke 	lstrcat,esi,ADDR szAnhookerDll
	
	invoke 	lstrcpy,edi,ADDR szWinDir
	invoke 	lstrcat,edi,ADDR szAnhookerDll	
	invoke 	CopyFile,esi,edi,0	; <-- COPY ANHOOKER.DLL KE WINDIR ;
	.if 	!eax
		jmp 	@bx
	.endif
	; #2 pdetector
	lea 	edi,lBuff
	invoke 	MyZeroMemory,edi,MAX_PATH
	invoke 	lstrcpy,edi,ADDR szMyDir
	invoke 	lstrcat,edi,ADDR szanPdetectordll
	lea 	esi,szInstallBuff
	invoke	MyZeroMemory,esi,MAX_PATH
	invoke 	lstrcpy,esi,ADDR szWinDir
	invoke 	lstrcat,esi,ADDR szanPdetectordll
	invoke 	CopyFile,edi,esi,0	; <-- COPY ANPDETECTOR.DLL KE WINDIR ;
	.if 	!eax
		jmp 	@bx
	.endif
	
	invoke 	InstallRange,30
	; ------- SIMPAN DI TEMPAT INSTALLASI ------- ;
	invoke 	MyZeroMemory,edi,MAX_PATH
	invoke 	lstrcpy,edi,ADDR szInstallLocation
	cText	a10,"ansav.exe"
	invoke 	lstrcat,edi,offset a10
	invoke 	FileExist,edi
	.if		eax
		invoke 	SetFileAttributes,edi,FILE_ATTRIBUTE_NORMAL
		invoke 	DeleteFile,edi
	.endif
	
	invoke 	CopyFile,ADDR szMyPath,edi,0	; <-- COPY FILE MASTER ANSAV.EXE ;
	.if 	!eax
	@bx2:
		ViewError	hInstallWnd,"Gagal meng-kopi file ansav.exe ke direktori instalasi, periksa hal ini."
		jmp 	@failed
	.endif
	
	invoke 	InstallRange,45
	; ------- BUATKAN DIREKTORI QUARANTINE ------- ;
	invoke 	InstallStatus,reparg("Creating directory...")
	invoke 	MyZeroMemory,edi,MAX_PATH
	invoke 	lstrcpy,edi,ADDR szInstallLocation
	
	;invoke 	lstrlen,edi
	strlen edi
	
	mov 	tmp,eax
	invoke 	lstrcat,edi,ADDR szQuarDirName
	invoke 	CreateDirectory,edi,0
	
	; ------- BUATKAN DIREKTORI PLUGINS ------- ;
	mov		eax,tmp
	mov 	byte ptr [edi+eax],0
	invoke 	lstrcat,edi,offset szPlugins
	invoke 	CreateDirectory,edi,0
	
	invoke 	InstallRange,50
	; ------- BUATKAN ANSAV INI ------- ;
	invoke 	InstallStatus,reparg("Building configuration...")
	lea 	edi,lBuff
	invoke 	MyZeroMemory,edi,MAX_PATH
	invoke 	lstrcpy,edi,ADDR szAnsavIniPath
	invoke 	lstrcat,edi,ADDR szStrip
	invoke 	CopyFile,ADDR szAnsavIniPath,edi,0
	
	push 	esi
	mov 	esi,SetConfigItem
	scall 	esi,offset szScanLevel,3	; <-- HIGH LEVEL ;
	scall 	esi,offset szMainScanBtn,1
	scall 	esi,offset szNoBipServ,0
	scall 	esi,offset szNoFQC,0
	scall 	esi,offset szNoScanMem,0
	scall 	esi,offset szShowResult,0
	scall 	esi,offset szNoActConfrm,0
	scall 	esi,offset szShowLog,0
	scall 	esi,offset szNoPlugins,0
	scall	esi,offset szEnableAngd,1	
	scall	esi,offset szEnableArchiveScan,1
	scall	esi,offset szZIP,1
	scall	esi,offset szJAR,1
	pop 	esi
	
	invoke 	InstallRange,65
	lea 	esi,szInstallBuff
	invoke 	MyZeroMemory,esi,MAX_PATH
	invoke 	lstrcpy,esi,ADDR szInstallLocation
	invoke 	lstrcat,esi,ADDR szAnsavIni
	invoke 	CopyFile,ADDR szAnsavIniPath,esi,0	; <-- COPY ANSAV.INI FILE TO INST LOCATION ;
	
	invoke 	InstallRange,70
	; back old ansav.ini
	mov 	edi,DeleteFile
	scall 	edi,offset szAnsavIniPath
	invoke 	CopyFile,ADDR lBuff,ADDR szAnsavIniPath,0
	lea 	eax,lBuff
	scall 	edi,eax
	
	; ------- Copy komponen ke Installation directory ------- ;
	invoke 	InstallStatus,reparg("Copying files...")
	lea 	edi,lBuff
	invoke 	MyZeroMemory,edi,MAX_PATH
	invoke 	lstrcpy,edi,ADDR szInstallLocation
	
	;invoke 	lstrlen,edi
	strlen edi
	
	mov 	tmp,eax
	invoke 	lstrcat,edi,ADDR szAnhookerDll
	invoke 	FileExist,edi	
	.if 	eax
		push 	edi
		call 	DelFile
	.endif
	invoke 	InstallRange,75
	invoke 	CopyFile,ADDR szAnhookerPath,edi,0; <-- COPY ANHOOKER KE INST DIR ;
	mov 	eax,tmp
	mov 	byte ptr [edi+eax],0
	invoke 	lstrcat,edi,ADDR szanPdetectordll
	invoke 	FileExist,edi	
	.if 	eax
		push 	edi
		call 	DelFile
	.endif
	lea 	esi,szInstallBuff
	invoke 	MyZeroMemory,esi,MAX_PATH
	invoke 	lstrcpy,esi,ADDR szMyDir
	
	;invoke 	lstrlen,esi
	strlen esi
	
	mov 	ebx,eax
	invoke 	lstrcat,esi,ADDR szanPdetectordll
	invoke 	CopyFile,esi,edi,0				; <-- COPY ANPDETECTOR KE INST DIR ;
	
	mov 	byte ptr [esi+ebx],0
	invoke 	lstrcat,esi,ADDR szReadmeTxt
	mov 	eax,tmp
	mov 	byte ptr [edi+eax],0
	invoke 	lstrcat,edi,ADDR szReadmeTxt
	invoke 	FileExist,edi
	.if 	eax
		push 	edi
		call 	DelFile
	.endif
	
	invoke 	CopyFile,esi,edi,0	; <-- readme.txt ;
	
	mov 	byte ptr [esi+ebx],0
	invoke 	lstrcat,esi,ADDR szVdbDat
	mov 	eax,tmp
	mov 	byte ptr [edi+eax],0
	invoke 	lstrcat,edi,ADDR szVdbDat
	invoke 	FileExist,edi
	.if 	eax
		push 	edi
		call 	DelFile
	.endif
	
	invoke 	CopyFile,esi,edi,0	; <-- vdb.dat ;
	
	mov 	byte ptr [esi+ebx],0
	invoke 	lstrcat,esi,ADDR szSteDll
	mov 	eax,tmp
	mov 	byte ptr [edi+eax],0
	invoke 	lstrcat,edi,ADDR szSteDll
	invoke 	FileExist,edi
	.if 	eax
		push 	edi
		call 	DelFile
	.endif
	
	invoke 	CopyFile,esi,edi,0	; <-- ste.dll ;
	
	mov 	byte ptr [esi+ebx],0
	invoke 	lstrcat,esi,ADDR szArcdll
	mov 	eax,tmp
	mov 	byte ptr [edi+eax],0
	invoke 	lstrcat,edi,ADDR szArcdll
	invoke 	FileExist,edi
	.if 	eax
		push 	edi
		call 	DelFile
	.endif
	
	invoke 	CopyFile,esi,edi,0	; <-- arc.dll ;
	
	mov 	byte ptr [esi+ebx],0
	invoke 	lstrcat,esi,ADDR szFixerFx
	mov 	eax,tmp
	mov 	byte ptr [edi+eax],0
	invoke 	lstrcat,edi,ADDR szFixerFx
	invoke 	FileExist,edi
	.if 	eax
		push 	edi
		call 	DelFile
	.endif
	
	invoke 	CopyFile,esi,edi,0	; <-- fixer.fx ;
	
	mov 	byte ptr [esi+ebx],0
	invoke 	lstrcat,esi,ADDR szTrustDataFile
	mov 	eax,tmp
	mov 	byte ptr [edi+eax],0
	invoke 	lstrcat,edi,ADDR szTrustDataFile
	invoke 	FileExist,edi
	.if 	eax
		push 	edi
		call 	DelFile
	.endif
	
	invoke 	CopyFile,esi,edi,0	; <-- trustzone.dat ;
	
	
	invoke 	InstallRange,80
	; ------- kopikan plugins2 ------- ;
	invoke 	InstallStatus,reparg("Copying plugins...")
	lea 	esi,szInstallBuff
	invoke 	MyZeroMemory,esi,MAX_PATH
	invoke 	lstrcpy,esi,ADDR szInstallLocation
	invoke 	lstrcat,esi,reparg("Plugins\")
	
	;invoke 	lstrlen,esi
	strlen esi
	
	mov 	tmp2,eax
	lea 	edi,lBuff
	invoke 	MyZeroMemory,edi,MAX_PATH
	invoke 	lstrcpy,edi,ADDR szPluginsPath
	invoke 	TruePath,edi
	
	;invoke 	lstrlen,edi
	strlen edi
	
	mov 	tmp,eax
	mov 	byte ptr [edi+eax],'*'
	invoke 	MyZeroMemory,ADDR wfd,sizeof WIN32_FIND_DATA
	invoke 	FindFirstFile,edi,ADDR wfd
	.if 	eax!=-1 && eax!=0
		mov 	hFind,eax
		.while 	eax
			lea 	eax,wfd.cFileName
			.if 	(byte ptr [eax]!='.') && !(dx & FILE_ATTRIBUTE_DIRECTORY)
				mov 	eax,tmp
				mov 	byte ptr [edi+eax],0
				lea 	edx,wfd.cFileName
				push 	edx
				invoke 	lstrcat,edi,edx
				
				mov 	eax,tmp2
				mov 	byte ptr [esi+eax],0
				pop 	edx
				invoke 	lstrcat,esi,edx
				invoke 	CopyFile,edi,esi,0
			.endif
			invoke 	FindNextFile,hFind,ADDR wfd
		.endw
		invoke 	FindClose,hFind
	.endif
	
	invoke 	InstallRange,90
	; ------- install service ------- ;
	invoke 	InstallStatus,reparg("Register Service...")
	
	;int InstallService( char* szName, char* szDesc, char* szPath )
	lea 	esi,lBuff
	invoke 	MyZeroMemory,esi,MAX_PATH
	invoke 	lstrcpy,esi,ADDR szWinDir
	invoke 	lstrcat,esi,reparg("ansavgd.exe")
	
	push 	esi
	push 	leatext("Ansav Guard")
	push 	offset szAnsavgd
	call 	InstallService
	.if 	!eax
		call 	GetLastError
		.if 	eax == ERROR_SERVICE_EXISTS
			ViewError 	hInstallWnd,"Gagal mendaftarkan layanan (service). Service sudah ada."
		.else
			ViewError 	hInstallWnd,"Gagal mendaftarkan layanan (service)."
		.endif
		
		jmp 	@failed
	.endif
	inc 	RoolBack
	
	; ------- BUAT NILAI REGISTRY ------- ;
	invoke 	InstallStatus,reparg("Updating System Registry...")
	
	; ------- encrypt string ------- ;
	lea 	esi,lBuff
	invoke 	MyZeroMemory,esi,MAX_PATH
	invoke 	anCrypto,esi,ADDR szInstallLocation
	invoke 	SetRegString,HKEY_LOCAL_MACHINE,offset szRegserv,offset szInstalledEx,esi
	
	invoke 	InstallRange,95
	
	; ------- MAKE SHORTCUT ------- ;
	.if 	CreateShortcut
		invoke 	InstallStatus,reparg("Creating shortcut...")
		lea 	esi,lBuff
		invoke 	MyZeroMemory,esi,MAX_PATH
		invoke 	lstrcpy,esi,ADDR szInstallLocation
		invoke 	lstrcat,esi,ADDR a10
		lea 	edi,szInstallBuff
		invoke 	MyZeroMemory,edi,MAX_PATH
		invoke 	GetRegString,edi,HKEY_LOCAL_MACHINE,
			offset szShellFolder,
			offset szCommonDesktop
		.if 	byte ptr [edi]==0
			@bx3:
			ViewError	hInstallWnd,"Gagal membuat pemintas pada desktop."
		.else
			invoke 	TruePath,edi
			invoke 	lstrcat,edi,offset szPlusEAlnk
			invoke 	CoInitialize,0
			invoke 	CoCreateLink,esi,edi
			.if 	eax
				invoke 	CoUninitialize
				jmp 	@bx3
			.endif
			invoke 	CoUninitialize
		.endif	
	.endif
	
	invoke 	InstallRange,100
	
	invoke 	MessageBox,hInstallWnd,reparg("Selesai"),ADDR szInstallTitle,MB_OK or MB_ICONINFORMATION
	
	
	; ------- sukses ------- ;
	invoke 	ShowInstP2,FALSE
	invoke 	ShowInstP3,FALSE
	invoke 	ShowInstP4,FALSE
	invoke 	ShowInstP5,FALSE
	
	cText 	sucks,"Pemasangan sukses..."
	invoke 	GetDlgItem,hInstallWnd,1021
	mov 	esi,eax
	invoke 	SetWindowText,esi,offset sucks
	invoke 	ShowWindow,esi,SW_SHOW
	invoke 	GetDlgItem,hInstallWnd,1008
	invoke 	ShowWindow,eax,SW_HIDE
	invoke 	SetDlgItemText,hInstallWnd,1005,reparg("Selesai")
	invoke 	AppendLogConsole,offset sucks
	mov 	Selesai,1
	;-------------------------------------- SELESAI ----------------------------------------;
	
	; ------- seh trapper ------- ;
	SehTrap 	__p
		ErrorDump 	"Pasang",offset Pasang,"Install.asm"
	SehEnd		__p
	
	
	ret

SetInstStatus:
	scall 	SetWindowText,hTxtStatus;,eax
	retn

@failed:
	; ------- details kegagalan ------- ;
	invoke 	ShowInstP2,FALSE
	invoke 	ShowInstP3,FALSE
	invoke 	ShowInstP4,FALSE
	invoke 	ShowInstP5,FALSE
	invoke 	GetDlgItem,hInstallWnd,1021
	invoke 	ShowWindow,eax,SW_SHOW
	invoke 	GetDlgItem,hInstallWnd,1008
	invoke 	ShowWindow,eax,SW_HIDE
	invoke 	SetDlgItemText,hInstallWnd,1005,reparg("Tutup")
	mov 	Selesai,1
	mov 	InstError,1
	SehPop
	ret
	
Pasang endp

Align 16

StartPasang proc
	
	
	invoke 	CreateThread,0,0,ADDR Pasang,0,0,ADDR brw
	invoke 	CloseHandle,eax
	
	ret

StartPasang endp

Align 16

DelFile proc lFile:DWORD
	
	invoke 	SetFileAttributes,lFile,FILE_ATTRIBUTE_NORMAL
	invoke 	DeleteFile,lFile
	ret

DelFile endp

Align 16

include 	inc/shellcode.asm

Align 16

UninstallANSAV proc uses esi edi ebx ecx edx
	LOCAL 	tmp,hFind:DWORD
	LOCAL 	manual:DWORD
	LOCAL 	wfd:WIN32_FIND_DATA
	LOCAL 	lpApi:DWORD
	
	; ------- seh installatioin ------- ;
	SehBegin 	__ua
	
	invoke 	GetDlgItem,hInstallWnd,1021
	invoke 	ShowWindow,eax,SW_HIDE
	invoke 	InstallStatus,reparg("Collecting information...")
	
	; ------- COLLECTIONG INFORMATION ------- ;
	invoke 	InstallRange,0
	; get Ansav installation path
	mov 	manual,0
	lea 	esi,szInstallLocation
	invoke 	MyZeroMemory,esi,MAX_PATH
	invoke 	GetRegString,esi, HKEY_LOCAL_MACHINE,offset szRegserv,offset szInstalledEx
	.if 	byte ptr [esi]
		lea 	edi,szInstallBuff
		invoke 	MyZeroMemory,edi,MAX_PATH
		invoke 	lstrcpy,edi,esi
		invoke 	anCrypto,esi,edi
	.else
		; ------- gagal mengidentifikasi lokasi installasi dari registry ------- ;
		invoke 	MessageBox,hInstallWnd,reparg("Gagal mengidentifikasi lokasi ANSAV, cari secara manual."),ADDR szInstallTitle,MB_OK
		
		; lakukan manual
		mov 	manual,1
		invoke	 BrowseForFolder,hInstallWnd,esi,ADDR szInstallTitle,reparg("Cari tempat anda memasang ANSAV."),0
	.endif
	
	invoke 	InstallRange,5
	Align 4
	
	.if 	byte ptr [esi]
		
		; ------- validasikan ------- ;
		lea 	edi,szInstallBuff
		invoke 	MyZeroMemory,edi,MAX_PATH
		invoke 	lstrcpy,edi,esi
		invoke 	TruePath,edi
		
		;invoke 	lstrlen,edi
		strlen edi
		
		mov 	tmp,eax
		invoke	lstrcat,edi,ADDR a10
		invoke 	FileExist,edi
		.if 	!eax
			jmp 	@tidakada
		.endif
	.else
		jmp 	@tidakada
	.endif
	invoke 	InstallRange,10
	
	;-------------------------------------- PROSES UNINSTALL ----------------------------------------;
	
	; ------- free all loaded module ------- ;
	; include plugins 
	
	mov 	ebx,FreeLibrary
	
	mov 	eax,hAnpDetector
	.if 	eax
		scall 	ebx,eax
	.endif
	
	mov 	eax,hArcMod
	.if 	eax
		scall 	ebx,eax
	.endif
	
	mov 	eax,hFixerMod
	.if 	eax
		scall 	ebx,eax
	.endif
	
	call 	UnStealth
	

	lea 	esi,PluginsTables
	assume 	edi:ptr PLUGINSIOCTL
@lp:
	lodsd
	test 	eax,eax
	jz 		@hbs
	mov 	edi,eax
	invoke 	FreeLibrary,[edi].hModule
	jmp 	@lp
@hbs:
	assume 	edi:nothing
	
	; kill agd
	invoke 	IsAnsavGuardActive?
	.if 	eax
		invoke 	InstallStatus,reparg("Stop Ansav Guard...")
		invoke 	EnableDisableAG,FALSE
		.if 	!eax
			jmp 	@failed
		.endif
	.endif
	
	invoke 	InstallRange,20
	invoke 	Sleep,2000

	; ------- hapus komponen di Windows dir ------- ;
	invoke 	InstallStatus,reparg("Deleting files...")
	invoke 	TruePath,ADDR szWinDir
	invoke 	MyZeroMemory,edi,MAX_PATH
	invoke 	lstrcpy,edi,ADDR szWinDir
	
	strlen edi
	
	mov 	tmp,eax
	invoke 	lstrcat,edi,offset szAnsavGdExe
	invoke 	FileExist,edi
IFDEF 	RELEASE
	.if 	eax
		invoke 	KillObjectForcely,edi	; <-- DEL ANSAVGD.EXE ;
		call 	verifdel
	.endif
ENDIF
	invoke 	InstallRange,21
	invoke 	Sleep,2000
	
	mov 	eax,tmp
	mov 	byte ptr [edi+eax],0
	invoke 	lstrcat,edi,ADDR szAnhookerDll
	invoke 	FileExist,edi
IFDEF 	RELEASE
	.if 	eax
		invoke 	DelFile,edi		; <-- DEL an32hk.dll ;
		call 	verifdel
	.endif
ENDIF
	
	invoke 	InstallRange,24
	
	mov 	eax,tmp
	mov 	byte ptr [edi+eax],0
	invoke 	lstrcat,edi,ADDR szanPdetectordll
	invoke 	FileExist,edi
IFDEF 	RELEASE
	.if 	eax
		invoke 	DelFile,edi		; <-- DEL anpdetector.dll ;
		call 	verifdel
	.endif
ENDIF
	
	invoke 	InstallRange,25
	; ------- hapus komponen di tempat installasi ------- ;
	lea 	esi,szInstallLocation
	invoke 	TruePath,esi
	invoke 	lstrcpy,edi,esi
	
	;invoke 	lstrlen,edi
	strlen edi
	
	mov 	tmp,eax
	
	invoke 	InstallRange,26
	invoke 	lstrcat,edi,ADDR szAnhookerDll
	invoke 	FileExist,edi
IFDEF 	RELEASE
	.if 	eax
		invoke 	DelFile,edi		; <-- DEL an32hk.dll ;
		call 	verifdel
	.endif
ENDIF
	
	invoke 	InstallRange,28
	mov 	eax,tmp
	mov 	byte ptr [edi+eax],0
	invoke 	lstrcat,edi,ADDR szanPdetectordll
	invoke 	FileExist,edi
IFDEF 	RELEASE
	.if 	eax
		invoke 	DelFile,edi		; <-- DEL anpdetector.dll ;
		call 	verifdel
	.endif
ENDIF
	
	invoke 	InstallRange,35
	
	mov 	eax,tmp
	mov 	byte ptr [edi+eax],0
	invoke 	lstrcat,edi,ADDR szAnsavIni
	invoke 	FileExist,edi
IFDEF 	RELEASE
	.if 	eax
		invoke 	DelFile,edi		; <-- DEL ansav.ini ;
		call 	verifdel
	.endif
ENDIF
	
	invoke 	InstallRange,40
	mov 	eax,tmp
	mov 	byte ptr [edi+eax],0
	invoke 	lstrcat,edi,ADDR szAgd32sys
	invoke 	FileExist,edi
IFDEF 	RELEASE
	.if 	eax
		invoke 	DelFile,edi		; <-- DEL agd32.sys ;
		call 	verifdel
	.endif
ENDIF

	invoke 	InstallRange,42
	mov 	eax,tmp
	mov 	byte ptr [edi+eax],0
	invoke 	lstrcat,edi,offset szReadmeTxt
	invoke 	FileExist,edi
IFDEF 	RELEASE
	.if 	eax
		invoke 	DelFile,edi		; <-- DEL readme.txt ;
		call 	verifdel
	.endif
ENDIF
	
	invoke 	InstallRange,43
	mov 	eax,tmp
	mov 	byte ptr [edi+eax],0
	invoke 	lstrcat,edi,offset szVdbDat
	invoke 	FileExist,edi
IFDEF 	RELEASE
	.if 	eax
		invoke 	DelFile,edi		; <-- DEL vdb.dat ;
		call 	verifdel
	.endif
ENDIF
	
	invoke 	InstallRange,44
	mov 	eax,tmp
	mov 	byte ptr [edi+eax],0
	invoke 	lstrcat,edi,offset szSteDll
	invoke 	FileExist,edi
IFDEF 	RELEASE
	.if 	eax
		invoke 	DelFile,edi		; <-- DEL ste.dll ;
		call 	verifdel
	.endif
ENDIF

	mov 	eax,tmp
	mov 	byte ptr [edi+eax],0
	invoke 	lstrcat,edi,offset szArcdll
	invoke 	FileExist,edi
IFDEF 	RELEASE
	.if 	eax
		invoke 	DelFile,edi		; <-- DEL arc.dll ;
		call 	verifdel
	.endif
ENDIF
	
	mov 	eax,tmp
	mov 	byte ptr [edi+eax],0
	invoke 	lstrcat,edi,offset szFixerFx
	invoke 	FileExist,edi
IFDEF 	RELEASE
	.if 	eax
		invoke 	DelFile,edi		; <-- DEL fixer.fx ;
		call 	verifdel
	.endif
ENDIF

	mov 	eax,tmp
	mov 	byte ptr [edi+eax],0
	invoke 	lstrcat,edi,offset szTrustDataFile
	invoke 	FileExist,edi
IFDEF 	RELEASE
	.if 	eax
		invoke 	DelFile,edi		; <-- DEL trustzone.dat ;
		call 	verifdel
	.endif
ENDIF
	
	; ------- delete SHORTCUT ------- ;
	invoke 	InstallStatus,reparg("Deleting Shortcut...")
	lea 	edi,szInstallBuff
	invoke 	MyZeroMemory,edi,MAX_PATH
	invoke 	GetRegString,edi,HKEY_LOCAL_MACHINE,
		offset szShellFolder,
		offset szCommonDesktop
	.if 	byte ptr [edi]
		invoke 	TruePath,edi
		invoke 	lstrcat,edi,offset szPlusEAlnk
		invoke 	DelFile,edi
		call 	verifdel
	.endif
	
	
	invoke 	InstallRange,45
	; ------- HAPUS PLUGINS ------- ;
	invoke 	InstallStatus,reparg("Deleting plugins...")
	invoke 	MyZeroMemory,edi,MAX_PATH
	invoke 	lstrcpy,edi,ADDR szInstallLocation
	invoke 	lstrcat,edi,ADDR szPlugins
	invoke 	TruePath,edi
	
	strlen edi
	
	mov 	tmp,eax
	mov 	byte ptr [edi+eax],'*'
	invoke 	MyZeroMemory,ADDR wfd,sizeof WIN32_FIND_DATA
	invoke 	FindFirstFile,edi,ADDR wfd
	.if 	eax!=-1 && eax!=0
		mov 	hFind,eax
		.while 	eax
			lea 	eax,wfd.cFileName
			.if 	(byte ptr [eax]!='.') && !(dx & FILE_ATTRIBUTE_DIRECTORY)
				mov 	eax,tmp
				mov 	byte ptr [edi+eax],0
				lea 	edx,wfd.cFileName
				push 	edx
				invoke 	lstrcat,edi,edx
IFDEF 	RELEASE
				invoke 	DelFile,edi
				call 	verifdel
ENDIF
			.endif
			invoke 	FindNextFile,hFind,ADDR wfd
		.endw
		invoke 	FindClose,hFind
	.endif
	
	invoke 	InstallRange,60
	; ------- delete all quarantine object ------- ;
	invoke 	InstallStatus,reparg("Deleting quarantine object...")
	invoke 	MyZeroMemory,edi,MAX_PATH
	invoke 	lstrcpy,edi,ADDR szInstallLocation
	invoke 	lstrcat,edi,ADDR szQuarDirName
	invoke 	TruePath,edi
	
	strlen edi
	
	mov 	tmp,eax
	mov 	byte ptr [edi+eax],'*'
	invoke 	MyZeroMemory,ADDR wfd,sizeof WIN32_FIND_DATA
	invoke 	FindFirstFile,edi,ADDR wfd
	.if 	eax!=-1 && eax!=0
		mov 	hFind,eax
		.while 	eax
			lea 	eax,wfd.cFileName
			.if 	(byte ptr [eax]!='.') && !(dx & FILE_ATTRIBUTE_DIRECTORY)
				mov 	eax,tmp
				mov 	byte ptr [edi+eax],0
				lea 	edx,wfd.cFileName
				push 	edx
				invoke 	lstrcat,edi,edx
				
				invoke 	DelFile,edi
				call 	verifdel
			.endif
			invoke 	FindNextFile,hFind,ADDR wfd
		.endw
		invoke 	FindClose,hFind
	.endif
	
	invoke 	InstallRange,75
	; ------- delete directory2 ------- ;
	invoke 	InstallStatus,reparg("Removing directory...")
	invoke 	MyZeroMemory,edi,MAX_PATH
	invoke 	lstrcpy,edi,ADDR szInstallLocation
	
	strlen edi
	
	mov 	tmp,eax
	invoke 	lstrcat,edi,ADDR szPlugins	; <-- RMDIR PLUGINS DIR ;
	invoke 	RemoveDirectory,edi
	call 	verifdel
	
	invoke 	InstallRange,80
	mov 	eax,tmp
	mov 	byte ptr [edi+eax],0
	invoke 	lstrcat,edi,ADDR szQuarDirName	; <-- RMDIR QUARANTINE DIR ;
	invoke 	RemoveDirectory,edi
	call 	verifdel
	
	invoke 	InstallRange,90
	; ------- hapus registry entry ------- ;
	invoke 	InstallStatus,reparg("Updating system registry...")
	invoke 	DeleteKeyValue,HKEY_LOCAL_MACHINE,ADDR szRegserv,ADDR szInstalledEx

	invoke 	InstallRange,92
	; ------- if error occur, copy log file to C:\ for further check (important for debugging)------- ;
	mov 	eax,tmp
	mov 	byte ptr [edi+eax],0
	invoke 	lstrcat,edi,ADDR szFileErrorLog
	invoke 	FileExist,edi
	.if 	eax
		invoke 	CopyFile,edi,reparg("C:\ansav_error_log.txt"),0
		invoke 	Sleep,200
		invoke 	DelFile,edi
		call 	verifdel
	.endif
	
	invoke 	InstallRange,95
	; ------- UNREGISTER SERVICE ------- ;
	invoke 	InstallStatus,reparg("Unregister service...")
	push 	offset szAnsavgd
	call 	RemoveService
	.if 	!eax
		ViewError	hInstallWnd,"Gagal menghapus Ansav Guard service..."
	.endif
	
	invoke 	InstallRange,96
	
	; ------- harakiri ------- ;

	
	; uses other process to help delete my self
	call 	GetInjectAbleProcess
	.if 	!eax
		call 	@noinjectable
	.endif
	
	
IFDEF 	DEBUG
	invoke 	GetCurrentProcess
ELSE
	invoke 	OpenProcess,PROCESS_ALL_ACCESS,0,eax
ENDIF
	.if 	eax
		mov 	esi,eax
		
		; ------- write shell code ------- ;
		invoke 	VirtualAllocEx,esi,0,SSelfDeleteSize,MEM_COMMIT,PAGE_EXECUTE_READWRITE
		.if 	!eax
			call 	@noinjectable
			jmp 	@nx
		.endif
		
		mov 	edi,eax
		
		invoke 	WriteProcessMemory,esi,edi,offset SSelfDelete,SSelfDeleteSize,ADDR brw
		.if 	!eax
			call 	@noinjectable
			jmp 	@nx
		.endif
		
		; ------- give live ------- ;
		invoke 	GetModuleHandle,reparg("Kernel32.dll")
		mov 	ebx,eax
		invoke 	GetProcAddress,ebx,reparg("SetFileAttributesA")
		mov 	lpApi,eax
		mov 	edx,edi
		add 	edx,@@SetFileAttributeSSD
		invoke 	WriteProcessMemory,esi,edx,ADDR lpApi,4,ADDR brw
		
		invoke 	GetProcAddress,ebx,reparg("DeleteFileA")
		mov 	lpApi,eax
		mov 	edx,edi
		add 	edx,@@DeleteFileSSD
		invoke 	WriteProcessMemory,esi,edx,ADDR lpApi,4,ADDR brw
		
		invoke 	GetProcAddress,ebx,reparg("RemoveDirectoryA")
		mov 	lpApi,eax
		mov 	edx,edi
		add 	edx,@@RemoveDirectorySSD
		invoke 	WriteProcessMemory,esi,edx,ADDR lpApi,4,ADDR brw
		
		invoke 	GetProcAddress,ebx,reparg("Sleep")
		mov 	lpApi,eax
		mov 	edx,edi
		inc 	edx
		invoke 	WriteProcessMemory,esi,edx,ADDR lpApi,4,ADDR brw
		
		invoke 	GetProcAddress,ebx,reparg("ExitThread")
		mov 	lpApi,eax
		mov 	edx,edi
		add 	edx,@@ExitThreadSSD
		invoke 	WriteProcessMemory,esi,edx,ADDR lpApi,4,ADDR brw
		
		invoke 	GetModuleHandle,reparg("user32.dll")
		mov 	ebx,eax
		invoke 	GetProcAddress,ebx,reparg("MessageBoxA")
		mov 	lpApi,eax
		mov 	edx,edi
		add 	edx,@@MessageBoxSSD
		invoke 	WriteProcessMemory,esi,edx,ADDR lpApi,4,ADDR brw
		
		; ------- write ansav path ------- ;
		invoke 	MyZeroMemory,ADDR szInstallBuff,MAX_PATH
		
		invoke 	lstrcpy,ADDR szInstallBuff,ADDR szInstallLocation
		invoke 	lstrcat,ADDR szInstallBuff,ADDR a10
		
		mov 	edx,edi
		add 	edx,SszAnsavPath
		invoke 	WriteProcessMemory,esi,edx,ADDR szInstallBuff,MAX_PATH,ADDR brw
		
IFDEF 	DEBUG
		call 	edi
ELSE
		invoke 	CreateRemoteThread,esi,0,0,edi,0,NULL,ADDR brw
ENDIF
		
		@nx:
		invoke 	InstallRange,100
		invoke 	CloseHandle,esi
		invoke	ExitProcess,0	; <-- EXIT NOW!! ;
	.endif
	
	
@endl:

	; ------- seh trapper ------- ;
	SehTrap 	__ua
		ErrorDump 	"UninstallANSAV",offset UninstallANSAV,"Install.asm"
	SehEnd 		__ua

IFDEF 	RELEASE
	invoke 	ExitThread,0
ENDIF

	ret
@failed:
	ViewError	hInstallWnd,"Gagal melakukan komunikasi dengan Ansav Guard"
	jmp 	@endl
@tidakada:
	.if 	manual
		mov 	eax,reparg("Tempat yang Anda pilih tidak terdapat ANSAV yang terpasang")
	.else
		mov 	eax,reparg("Tidak dapat mengidentifikasi tempat terpasangnya ANSAV")
	.endif
	ViewError 	hInstallWnd,eax
	invoke 	InstallRange,0
	mov 	InstalAbort,1
	jmp 	@endl

SehPop
ret
verifdel:
	test 	eax,eax
	jnz 	@del
		invoke 	MyZeroMemory,ADDR szInstallBuff2,1024
		jmp 	@F
			szCantDelete db "File/Dir berikut gagal dihapus :",13,10
						 db '"%s"',13,10
						 db 'Anda bisa menghapusnya secara manual setelah komputer dihidupkan ulang',0 
		@@:
		lea 	edx,szCantDelete
		invoke 	wsprintf,ADDR szInstallBuff2,edx,edi
		invoke 	MessageBox,hInstallWnd,ADDR szInstallBuff2,ADDR szInstallTitle,MB_OK
	@del:
	retn
@noinjectable:
	ViewError	hInstallWnd,"Gagal menghapus diri sendiri. Lakukan secara manual"
	retn
	 
UninstallANSAV endp

Align 16

StartUninstallANSAV proc
	
	invoke 	CreateThread,0,0,ADDR UninstallANSAV,0,0,ADDR brw
	invoke 	CloseHandle,eax
	
	ret

StartUninstallANSAV endp

Align 16


