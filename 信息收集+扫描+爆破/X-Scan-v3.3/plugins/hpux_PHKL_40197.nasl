
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(40607);
 script_version ("$Revision: 1.2 $");
 script_name(english: "HP-UX Security patch : PHKL_40197");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHKL_40197 security update");
 script_set_attribute(attribute: "description", value:
"11.31 ttrace(2) cumulative patch");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//hp-ux_patches/11.X/PHKL_40197");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHKL_40197");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "HP-UX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/HP-UX/swlist");
 exit(0);
}

include("hpux.inc");
if ( ! hpux_check_ctx ( ctx:"11.31 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHKL_40197 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"ProgSupport.C-INC", version:"B.11.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"ProgSupport.PAUX-ENG-A-MAN", version:"B.11.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE2-KRN", version:"B.11.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE2-KRN", version:"B.11.31") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
