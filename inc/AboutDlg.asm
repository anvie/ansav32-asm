;------------------------------------------------------------------------------;
;
;   ANSAV An's Antivirus
;   Copyright (C) 2007-2008 Muqorrobien Ma'rufi a.k.a 4NV|e
;   
;   Muqorrobien Ma'rufi a.k.a 4NV|e
;   anvie_2194 @ yahoo.com
;   http://www.ansav.com
;   PP. Miftahul Huda Blok C Siwatu Wonosobo 56352 Jawa Tengah Indonesia
;   
;
;------------------------------------------------------------------------------;

; ------- AboutDlg.asm ------- ;
;
.code

align 16

BuildAboutInfo proc uses edi
    LOCAL   szUserB[256+1]:BYTE
    LOCAL   dBuff:DWORD
    LOCAL   lbrw:DWORD
    
    
    jmp     @F
        align 16
        szAboutF    db "ANSAV (An's Antivirus)",13,10
                    db "Version %d.%d.%d",13,10
                    db "Last Database Update : %d.%d.%d",13,10
                    db "http://www.ansav.com",13,10
                    db "Coded in 100%% pure Assembly",13,10
                    ;db "Copyright ",0A9h," 2006-2007 4NV|e",13,10
                    db "Copyright ",0A9h," 2006-2008",13,10,"4NV|e & movzx",13,10 ;04-09-2007 by movzx
                    db 13,10
                    db "Registered to : %s",13,10,13,10
                    db "Uses aPlib compression algorithm "
                    db "for compressing quarantine object "
                    ;db "written by Joergen Ibsen (Jibz).",13,10,13,10,0 
                    db "written by Joergen Ibsen (Jibz).",13,10,13,10 ;04-09-2007 by movzx
                    db "Uses ADE32 (Advanced Disassembler Engine 32) by z0mbie/29A",13,10
                    db "and lingo in strlen algorithm",13,10,0
                    
        szCredit    db "Ansav team :",13,10
                    db "Omponk (site admin)",13,10
                    db "rUsh_man (supporter)",13,10
                    db "lucuBRB (forum admin)",13,10
                    db "Willgand (forum admin)",13,10
                    db "bang_thambax (forum moderator)",13,10
                    db "Madsyair (forum moderator)",13,10,13,10
                    db "Thanks to :",13,10
                    db "KetilO, Iczelion, ap0x, Oleh yuschuk, "
                    db "Y0da, z0mbie, HollyFather, Ratter, "
                    db "ScareByte, "
                    db "Maseko (www.maseko.com), "
                    db "Kalayana, Vyrist13, Eqhien_ceng, Dwi Agus"
                    db "Siberat, Bagus_badboy, Zuric, "
                    db "Lord_nara, hary_ds, NeMeSiS_ByTe, "
                    db "a2i3s, SaltyFish, "
                    db "ccpb community and all ansaver",13,10,13,10,0
                    
                    AboutCreditSize equ ($ - offset szAboutF) + (512)
                    
        szPublic    db "PUBLIC",0
    @@:
    
    valloc  AboutCreditSize
    test    eax,eax
    jnz     @F
        ret
    @@:
    mov     dBuff,eax
    
    lea     edi,szUserB
    invoke  MyZeroMemory,edi,256
    
    invoke  GetUserName,edi,ADDR lbrw
    .if     byte ptr [edi] == 0
        invoke  lstrcpyn,edi,ADDR szPublic,256
    .endif
    
        lea     eax,szPublic
    push    eax
    push    dwRDYear
    push    dwRDMonth
    push    dwRDDay
    push    VerRevision
    push    VerMinor
    push    VerMajor
        lea     eax,szAboutF
    push    eax
        ;lea    eax,lBuff
    push    dBuff
    call    wsprintf
    add     esp,4*9
    
    invoke  lstrcat,dBuff,offset szCredit
    invoke  SetWindowText,hTxtAboutInfo,dBuff
    
    vfree   dBuff
    
    ret

BuildAboutInfo endp

align 16

AboutDlgProc proc   hWin:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
    LOCAL hDC   :DWORD
    LOCAL hOld  :DWORD
    LOCAL memDC :DWORD
    LOCAL ps,tmp:DWORD
    
    mov     eax,uMsg
    .if     eax == WM_INITDIALOG
    
        .if     TimeForBlind
            call    ChangeRandomString
            invoke  SetWindowText,hWin,ADDR szRandomString
        .endif
        
        invoke  GetDlgItem,hWin,1001 ; ------- Txt about info ------- ;
        mov     hTxtAboutInfo,eax
        
        call    BuildAboutInfo
        
        invoke  UpdateWindow,hWin
        invoke  SetFocus,hWin
    .elseif     eax == WM_COMMAND
        mov     eax,wParam
        .if     eax == 101 ; ------- Close ------- ;
            
            invoke  EndDialog,hWin,0
            
        .endif
    .elseif     eax == WM_PAINT
        invoke LocalAlloc,LPTR,sizeof PAINTSTRUCT
        mov     ps,eax
        
        invoke  BeginPaint,hWin,ps
        mov     hDC, eax
        
        invoke  CreateCompatibleDC,hDC
        mov     memDC, eax
        
        invoke  LoadBitmap,hInstance,IMG_LOGO_SMALL
        invoke  SelectObject,memDC,eax
        mov     hOld, eax
        
        invoke  BitBlt,hDC,0,0,300,50,memDC,0,0,SRCCOPY
        invoke  SelectObject,hDC,hOld
        invoke  DeleteDC,memDC
        
        invoke  CreateCompatibleDC,hDC
        mov     memDC,eax
        invoke  LoadBitmap,hInstance,IMG_PISTOL
        invoke  SetBmpColor,eax
        mov     tmp,eax
        invoke  SelectObject,memDC,eax
        mov     hOld,eax
        invoke  BitBlt,hDC,9,70,64,64,memDC,0,0,SRCAND
        invoke  SelectObject,hDC,hOld
        invoke  DeleteDC,memDC
        
        invoke  EndPaint,hWin,ps
        invoke  ReleaseDC,hWin,hDC
        
        invoke  LocalFree,ps
        invoke  DeleteObject,tmp
    .endif
    
    
    xor     eax,eax
    ret

AboutDlgProc endp

align 16


ShowAboutDialog proc hWin:DWORD
    
    invoke  DialogBoxParam,hInstance,IDD_ABOUT,hWin,ADDR AboutDlgProc,0
    ret

ShowAboutDialog endp

align 16

