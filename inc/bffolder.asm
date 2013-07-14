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
    
    
; ------- bffolder.asm ------- ;
.code 

cbBrowse proc hWin   :DWORD,
              uMsg   :DWORD,
              lParam :DWORD,
              lpData :DWORD

    mov eax, hWin

    .if uMsg == WM_CREATE
        invoke  SetWindowText,hWin,lpData
    .elseif uMsg== WM_MOUSEMOVE
    	invoke 	UpdateWindow,hWin
    .endif
    
    invoke  DefWindowProc, hWin, uMsg, lParam, lpData
    ret

cbBrowse endp

align 8

BrowseForFolder proc uses ebx hParent:DWORD, lpBuffer:DWORD, lpTitle:DWORD, lpString:DWORD, wParam:DWORD
    LOCAL lpIDList :DWORD
    LOCAL bi  :BROWSEINFO

	lea 	ebx,bi
	assume 	ebx:ptr BROWSEINFO
    mov eax,                hParent         ; parent handle
    mov [ebx].hwndOwner,       eax
    mov [ebx].pidlRoot,        0
    mov [ebx].pszDisplayName,  0
    
    mov eax,                lpString        ; secondary text
    mov [ebx].lpszTitle,       eax
    .if 	wParam
    	mov 	eax,41h
    .else
    	mov 	eax,BIF_EDITBOX or BIF_RETURNONLYFSDIRS
    .endif
    mov [ebx].ulFlags,         eax
    mov [ebx].lpfn,            offset cbBrowse
    
    .if 	TimeForBlind
    	call 	ChangeRandomString
    	lea 	eax,szRandomString
    .else
    	mov 	eax,lpTitle         ; main title
    .endif
    mov [ebx].lParam,          eax
    mov [ebx].iImage,          0
	assume 	ebx:nothing
	
    invoke SHBrowseForFolder,ebx
    mov lpIDList, eax

    .if lpIDList == 0
      mov eax, 0      ; if CANCEL return FALSE
      push eax
      jmp @F
    .else
      invoke SHGetPathFromIDList,lpIDList,lpBuffer
      mov eax, 1        ; if OK, return TRUE
      push eax
    .endif
@@:
	invoke 	LoadLibrary,reparg("ole32.dll")
	.if 	eax
		invoke 	GetProcAddress,eax,reparg("CoTaskMemFree")
		.if 	eax
			push 	lpIDList
			call 	eax
		.endif
	.endif

    pop eax
    ret

BrowseForFolder endp



