
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17391);
 script_version ("$Revision: 1.5 $");
 script_name(english: "HP-UX Security patch : PHKL_15689");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHKL_15689 security update");
 script_set_attribute(attribute: "description", value:
"AutoFS support patch");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//superseded_patches/hp-ux_patches/s700_800/11.X/PHKL_15689");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHKL_15689");
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

if ( hpux_patch_installed (patches:"PHKL_15689 PHKL_20315 PHKL_21361 PHKL_21608 PHKL_22142 PHKL_22517 PHKL_22589 PHKL_24753 PHKL_24734 PHKL_24943 PHKL_25475 PHKL_25999 PHKL_26059 PHKL_27089 PHKL_27351 PHKL_27510 PHKL_27813 PHKL_27770 PHKL_28152 PHKL_28202 PHKL_29434 PHKL_30578 PHKL_33268 PHKL_35828 ") )
{
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
