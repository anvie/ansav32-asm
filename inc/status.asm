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


;-------------------------------------- status.asm ----------------------------------------;

.data?

	hStatusWnd dd ?

.code

align 16

StatusProc proc hWin:DWORD, uMsg:DWORD, wParam:DWORD, lParam:DWORD
	
	mov 	eax,uMsg
	.if 		eax==WM_INITDIALOG
		
		m2m 	hStatusWnd,hWin
		
		push 	esi
		
		mov 	esi,hWin
		invoke 	GetDlgItem,esi,1001
		invoke 	SetWindowText,eax,lParam
		
		invoke 	ShowWindow,esi,SW_SHOW
		invoke 	SetForegroundWindow,esi
		invoke 	UpdateWindow,esi
		invoke 	SetFocus,esi
		
		pop 	esi
		
	.elseif 	eax==WM_COMMAND
		
	.elseif 	eax==WM_CLOSE
		invoke 	DestroyWindow,hWin
	.endif
	
	xor 	eax,eax
	ret

StatusProc endp

align 16

PopupStatus proc status:DWORD
	
	invoke 	CreateDialogParam,hInstance,IDD_STATUS,hMainWnd,offset StatusProc,status
	ret

PopupStatus endp



align 16

EndStatus proc
	
	invoke 	DestroyWindow,hStatusWnd
	ret

EndStatus endp








