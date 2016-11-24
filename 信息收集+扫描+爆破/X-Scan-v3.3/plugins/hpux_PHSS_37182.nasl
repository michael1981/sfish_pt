
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(28270);
 script_version ("$Revision: 1.8 $");
 script_name(english: "HP-UX Security patch : PHSS_37182");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHSS_37182 security update");
 script_set_attribute(attribute: "description", value:
"X OV OVO8.X IA-64 JavaGUI client A.08.27");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_37182");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHSS_37182");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "HP-UX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/HP-UX/swlist");
 exit(0);
}

include("hpux.inc");
if ( ! hpux_check_ctx ( ctx:"11.23 11.31 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_37182 PHSS_37565 PHSS_38202 PHSS_38853 PHSS_39326 PHSS_39895 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OVOPC-WWW.OVOPC-WWW-ENG", version:"A.08.20.050") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-WWW.OVOPC-WWW-GUI", version:"A.08.20.050") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-WWW.OVOPC-WWW-JPN", version:"A.08.20.050") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-WWW.OVOPC-WWW-KOR", version:"A.08.20.050") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-WWW.OVOPC-WWW-SCH", version:"A.08.20.050") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVOPC-WWW.OVOPC-WWW-SPA", version:"A.08.20.050") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
