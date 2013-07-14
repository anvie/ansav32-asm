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

.data
      stWin db "STATIC",0
.code

DisplayBmp proc hParent:DWORD,bmpID:DWORD,x:DWORD,y:DWORD,ID:DWORD

    LOCAL hModule:DWORD
    LOCAL hBmp   :DWORD
    LOCAL hImage :DWORD

    invoke GetModuleHandle,NULL
    mov hModule, eax

    invoke CreateWindowEx,WS_EX_LEFT,
            ADDR stWin,NULL,
            WS_CHILD or WS_VISIBLE or SS_BITMAP,
            x,y,10,10,hParent,ID,
            hModule,NULL

    mov hImage, eax

    invoke LoadBitmap,hModule,bmpID
    mov hBmp, eax

    invoke SendMessage,hImage,STM_SETIMAGE,IMAGE_BITMAP,hBmp

    mov eax, hImage
    ret

DisplayBmp endp





VerticalTile proc hWin:DWORD,bmpID:DWORD,cnt:DWORD

  ; hWin  = is the window to tile the bitmap on
  ; bmpID = is the RESOURCE ID number
  ; cnt   = is the number of times to tile from top down

    LOCAL hndl:DWORD
    LOCAL tp  :DWORD
    LOCAL step:DWORD
    LOCAL lpz :DWORD
    LOCAL Rct :RECT

    cmp cnt, 1
    jl thOut

    mov tp, 370

    invoke DisplayBmp,hWin,bmpID,1,tp,150
    mov hndl, eax

    cmp cnt, 1
    jle thOut

    invoke GetWindowRect,hndl,ADDR Rct

    mov eax, Rct.top
    mov ecx, Rct.bottom
    sub ecx, eax
    mov step, ecx

    add tp, ecx

    mov lpz, 1      ; use as counter

  @@:
    invoke DisplayBmp,hWin,bmpID,1,tp,150
    mov eax, step
    add tp, eax
    inc lpz
    mov eax, cnt
    cmp lpz, eax
    jne @B

  thOut:

    ret

VerticalTile endp