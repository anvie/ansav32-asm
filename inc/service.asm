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


;-------------------------------------- service.asm ----------------------------------------;

.code

InstallService::

        push ebp
        mov ebp,esp
        push esi

        push 2
        push 0
        push 0
        call OpenSCManager
        mov esi,eax
        test esi,esi
        jnz @F
        pop esi
        pop ebp
        retn

@@:

        mov eax,dword ptr ss:[ebp+010h]
        push 0
        mov ecx,dword ptr ss:[ebp+0ch]
        push 0
        mov edx,dword ptr ss:[ebp+8]
        push 0
        push 0
        push 0
        push eax
        push 1
        push 2
        push 0110h
        push 0f01ffh
        push ecx
        push edx
        push esi
        call CreateService
        test eax,eax
        jnz @F
        pop esi
        pop ebp
        retn

@@:

        push 	edi
        mov 	edi,CloseServiceHandle 
        push 	eax
        call 	edi
        push 	esi
        call 	edi
        pop 	edi
        xor 	eax,eax
        inc 	eax
        pop 	esi
        pop 	ebp
        retn                                

align 16

RemoveService::                             

        sub esp,01ch
        push esi
        push edi
        push 2
        push 0
        push 0
        call OpenSCManager 
        mov edi,eax
        test edi,edi
        jnz @F
        pop edi
        pop esi
        add esp,01ch
        retn

@@:

        mov eax,dword ptr ss:[esp+028h]
        push 0f01ffh
        push eax
        push edi
        call OpenService 
        mov esi,eax
        test esi,esi
        jnz @F
        pop edi
        pop esi
        add esp,01ch
        retn

@@:

        lea ecx,dword ptr ss:[esp+8]
        push ecx
        push esi
        call QueryServiceStatus 
        test eax,eax
        jnz @F
        pop edi
        pop esi
        add esp,01ch
        retn

@@:

        cmp dword ptr ss:[esp+0ch],1
        je @tool_004010EA
        lea edx,dword ptr ss:[esp+8]
        push edx
        push 1
        push esi
        call ControlService 
        test eax,eax
        jnz @tool_004010DF
        pop edi
        pop esi
        add esp,01ch
        retn

@tool_004010DF:

        push 01f4h
        call Sleep 

@tool_004010EA:

        push esi
        call DeleteService 
        test eax,eax
        jnz @F
        pop edi
        pop esi
        add esp,01ch
        retn

@@:

        push esi
        mov esi,CloseServiceHandle
        call esi
        push edi
        call esi
        pop edi
        xor 	eax,eax
        inc 	eax
        pop esi
        add esp,01ch
        retn                         

align 16

SetServiceStartType proc uses esi edi lType:DWORD
	LOCAL	retv:DWORD
	
	mov 	retv,0
	invoke 	OpenSCManager,0,0,SC_MANAGER_ALL_ACCESS
	.if 	eax
		mov 	esi,eax
		
		invoke 	OpenService,esi,ADDR szAnsavgd,SERVICE_CHANGE_CONFIG or SERVICE_QUERY_CONFIG or SERVICE_QUERY_STATUS
		.if 	eax
			mov 	edi,eax
			
			invoke 	ChangeServiceConfig,edi,
				SERVICE_WIN32_OWN_PROCESS or SERVICE_INTERACTIVE_PROCESS,
				lType,	
				SERVICE_ERROR_NORMAL,
				0,0,0,0,0,0,0
			
			invoke 	CloseServiceHandle,edi
		.else
			call 	GetLastError
			.if 	eax != ERROR_SERVICE_DOES_NOT_EXIST
				mov 	eax,1
			.endif
		.endif
		invoke 	CloseServiceHandle,esi
	.endif
	
	mov 	eax,retv
	ret

SetServiceStartType endp


