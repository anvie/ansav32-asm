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

;-------------------------------------- Admin.asm ----------------------------------------;
; for check privilege
.data
	hCurrentThread		dd 0
	hAccessToken		dd 0
	hCurrentProcess		dd 0
	dwInfoBufferSize	dd 0
	bSuccess			dd 0
	pInfoBuffer			dd 0
	siaNtAuthority		SID_IDENTIFIER_AUTHORITY <SECURITY_NT_AUTHORITY>
	psidAdministrators	dd 0
.code

;-------------------------------------- Admin right check ----------------------------------------;
IsAdmin proc

	; ------- seh installation ------- ;
	SehBegin	__ia

	invoke	GetCurrentThread
	mov		hCurrentThread, eax
	invoke	OpenThreadToken, hCurrentThread, TOKEN_QUERY, TRUE, ADDR hAccessToken
	.if eax == 0
		invoke	GetLastError
		.if eax != ERROR_NO_TOKEN
			mov	eax, FALSE
			SehPop
			ret
		.endif
		invoke	GetCurrentProcess
		mov		hCurrentProcess, eax
		invoke	OpenProcessToken, hCurrentProcess, TOKEN_QUERY, ADDR hAccessToken
		.if eax == 0
			mov		eax, FALSE
			SehPop
			ret
		.endif
	.endif
	invoke	GetTokenInformation, hAccessToken, TokenGroups, NULL, NULL, ADDR dwInfoBufferSize
	.if dwInfoBufferSize > 0
		invoke	GlobalAlloc, GMEM_FIXED, dwInfoBufferSize
		mov		pInfoBuffer, eax
		invoke	GetTokenInformation, hAccessToken, TokenGroups, pInfoBuffer, dwInfoBufferSize, ADDR dwInfoBufferSize
	.endif
	mov		bSuccess, eax
	invoke	CloseHandle, hAccessToken

	.if bSuccess == 0
		mov		eax, FALSE
		SehPop
		ret
	.endif

	invoke	AllocateAndInitializeSid, ADDR siaNtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, ADDR psidAdministrators
	.if	eax == 0
		mov		eax, FALSE
		SehPop
		ret
	.endif
	
	mov		bSuccess, FALSE
	
	mov		ebx, pInfoBuffer
	mov		ecx, TOKEN_GROUPS.GroupCount[ebx]
	xor		esi, esi
	.while	esi < ecx
		push	esi
		push	ecx
		mov		ecx, TOKEN_GROUPS.Groups.Sid[ebx]
		mov		eax, sizeof TOKEN_GROUPS.Groups
		xor		edx, edx
		mul		esi									;eax * esi -> eax
		add		ecx, eax
		invoke	EqualSid, psidAdministrators, ecx
		pop		ecx
		pop		esi
		.if eax != 0
			mov		bSuccess, TRUE
			.break
		.endif
		inc		esi
	.endw
	invoke	FreeSid, psidAdministrators
	invoke	GlobalFree, pInfoBuffer
	
	; ------- seh trapper ------- ;
	SehTrap 	__ia
		ErrorDump 	"IsAdmin",offset IsAdmin,"admin.asm"
	SehEnd 		__ia
	
	
	mov eax, bSuccess
	ret
IsAdmin endp
