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


;-------------------------------------- servpass.asm ----------------------------------------;

.code


ServPassProc proc hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
	
	mov 	eax,uMsg
	.if 	eax == WM_INITDIALOG
		invoke 	SetWindowText,hWin,reparg("Member identifier")
	.elseif 	eax == WM_COMMAND
		mov 	eax,wParam
		and 	eax,0FFFFh
		.if 	eax == 1001	; <-- OK ;
			mov 	szUserPassword[0],0
			invoke 	GetDlgItemText,hWin,1002,offset szUserPassword,12
			.if 	!szUserPassword[0]
				invoke 	MessageBox,hWin, \
						reparg("Please enter passcode."), \
						offset szAppName,MB_OK
				invoke 	GetDlgItem,hWin,1002
				invoke 	SetFocus,eax
				return_0
			.endif
			invoke 	EndDialog,hWin,offset szUserPassword
		.elseif 	eax==1004
			invoke 	EndDialog,hWin,0
		.endif
	.endif
	
	xor 	eax,eax
	ret

ServPassProc endp

align 16

StartServPassProc proc
	
	invoke 	DialogBoxParam,hInstance,IDD_SERVPASS,hUpdateWnd,offset ServPassProc,0
	ret

StartServPassProc endp
