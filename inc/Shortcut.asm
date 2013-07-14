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

include \masm32\com\include\oaidl.inc
include \masm32\com\include\shlobj.inc
include \masm32\include\ole32.inc
includelib \masm32\lib\ole32.lib

;-------------------------------------- Shortcut.asm ----------------------------------------;
.data
  ; IPersistFile Interface 
  IPersistFile            STRUCT DWORD
       IPersistFile_QueryInterface       comethod3       ?
       IPersistFile_AddRef               comethod1       ?
       IPersistFile_Release              comethod1       ?
       IPersistFile_GetClassID           comethod2       ?
       IPersistFile_IsDirty              comethod1       ?
       IPersistFile_Load                 comethod3       ?
       IPersistFile_Save                 comethod3       ?
       IPersistFile_SaveCompleted        comethod2       ?
       IPersistFile_GetCurFile           comethod2       ?
 IPersistFile            ENDS
.code

CoCreateLink PROC pszPathObj:DWORD, pszPathLink:DWORD
 ; CreateLink - uses the shell's IShellLink and IPersistFile interfaces 
 ;   to create and store a shortcut to the specified object. 
 ; Returns the hresult of calling the member functions of the interfaces. 
 ; pszPathObj - address of a buffer containing the path of the object. 
 ; pszPathLink - address of a buffer containing the path where the 
 ;   shell link is to be stored. 
 ; addapted from MSDN article "Shell Links"
 ;  deleted useless "description" method
 ;  added set icon location method

    LOCAL   pwsz    :DWORD         
    LOCAL   psl     :DWORD         
    LOCAL   ppf     :DWORD       
    LOCAL   hResult :DWORD       
    LOCAL   hHeap   :DWORD    
    LOCAL 	len		:DWORD   

.data
CLSID_ShellLink     GUID       sCLSID_ShellLink
IID_IShellLink      GUID       sIID_IShellLink
IID_IPersistFile    GUID       {00000010bH, 00000H, 00000H, \
                               {0C0H, 000H, 000H, 000H, 000H, 000H, 000H, 046H}}

.code
    ; first, get some heap for a wide buffer
    invoke GetProcessHeap
    mov hHeap, eax
    invoke HeapAlloc, hHeap, NULL, MAX_PATH * 2
    mov pwsz, eax
    ; Get a pointer to the IShellLink interface. 
    invoke CoCreateInstance, ADDR CLSID_ShellLink, NULL,  
                             CLSCTX_INPROC_SERVER, 
                             ADDR IID_IShellLink, ADDR psl 
    mov hResult, eax
    test eax, eax
    .IF SUCCEEDED 
        ; Query IShellLink for the IPersistFile 
        ; interface for saving the shortcut
        coinvoke psl, IShellLink, QueryInterface, ADDR IID_IPersistFile, ADDR ppf
        mov hResult, eax
        test eax, eax
        .IF SUCCEEDED 
            ; Set the path to the shortcut target 
            coinvoke psl, IShellLink, SetPath, pszPathObj
            mov hResult, eax
            
            ; ------- added by anvie ------- ;
            mov 	esi,pszPathObj
            invoke 	lstrlen,esi
            mov ecx,eax
            @lp:
            	cmp 	byte ptr [esi+ecx],'\'
            	jne 	@F
            		mov 	byte ptr [esi+ecx],0
            		mov 	eax,esi
            		add 	eax,ecx
            		mov 	len,eax
            		jmp 	@ots
            	@@:
           	loop @lp
           	@ots:
            coinvoke psl, IShellLink, SetWorkingDirectory, esi
            mov 	eax,len
            mov 	byte ptr [eax],'\'
            
            ; add the  description, use first icon found
            coinvoke psl, IShellLink, SetIconLocation, pszPathObj, 0 
            mov hResult, eax
            ; change string to Unicode. 
            ; (COM typically expects Unicode strings)
            invoke MultiByteToWideChar, CP_ACP, 0, pszPathLink, 
                                        -1, pwsz, MAX_PATH
            ; Save the link by calling IPersistFile::Save
			coinvoke ppf, IPersistFile, Save, pwsz, TRUE
            ;mov eax, hResult
            mov 	hResult,eax
            ; release the IPersistFile ppf pointer
            coinvoke ppf, IPersistFile, Release
            mov hResult, eax
        .ENDIF
        ; release the IShellLink psl pointer
        coinvoke psl, IShellLink, Release
        mov hResult, eax
    .ENDIF
    ; free our heap space
    invoke HeapFree, hHeap, NULL, pwsz
    mov eax, hResult    ; since we reuse this variable over and over,
                        ;  it contains the last operations result
    ret
CoCreateLink ENDP