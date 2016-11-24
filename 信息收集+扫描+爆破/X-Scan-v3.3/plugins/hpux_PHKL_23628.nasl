
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(16721);
 script_version ("$Revision: 1.5 $");
 script_name(english: "HP-UX Security patch : PHKL_23628");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHKL_23628 security update");
 script_set_attribute(attribute: "description", value:
"probe,sysproc,shmem,thread cumulative patch");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//patches_with_warnings/hp-ux_patches/s700_800/11.X/PHKL_23628");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHKL_23628");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "HP-UX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/HP-UX/swlist");
 exit(0);
}

include("hpux.inc");
if ( ! hpux_check_ctx ( ctx:"11.00 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHKL_23628 PHKL_23812 PHKL_23813 PHKL_23857 PHKL_24015 PHKL_24116 PHKL_24273 PHKL_24457 PHKL_24612 PHKL_24826 PHKL_24971 PHKL_25164 PHKL_25188 PHKL_25210 PHKL_25525 PHKL_25906 PHKL_26800 PHKL_27157 PHKL_27238 PHKL_27364 PHKL_27759 PHKL_27919 PHKL_27994 PHKL_28053 PHKL_28180 PHKL_28766 PHKL_29345 PHKL_29648 PHKL_30190 PHKL_30709 PHKL_31867 PHKL_33500 PHKL_33819 PHKL_34341 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.CORE-KRN", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"ProgSupport.C-INC", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE2-KRN", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE2-KRN", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
