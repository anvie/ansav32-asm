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


; ------- an packer detector ------- ;
.const

	PACKER_UPX			equ 100
	PACKER_MEW			equ 101
	PACKER_ASPACK		equ 102
	PACKER_WINUPACK		equ 103
	PACKER_PETITE		equ 104
	PACKER_TELOCK		equ 105
	PACKER_NPACK		equ 106
	PROTECTOR_ANCAPS	equ 107
	PACKER_FSG			equ 108
	PACKER_PEC2			equ 109
	
	
	COMPILER_VCPP_6					equ 501
	COMPILER_VCPP_7					equ 502
	COMPILER_VB_6					equ 503
	COMPILER_BORLAND_DELPHI_3 		equ 504
	COMPILER_BORLAND_DELPHI_4_5		equ 505
	COMPILER_VCPP_7b				equ 506
	COMPILER_VCPP_8					equ 507
	COMPILER_BORLAND_CPP			equ 508
	INSTALLER_NULLSOFT				equ 509
	SFX_WINZIP_32BIT				equ 510
	COMPILER_BORLAND_DELPHI_2		equ 511
	INSTALLER_WISE					equ 512

.code
