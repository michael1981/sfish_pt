
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(16965);
 script_version ("$Revision: 1.6 $");
 script_name(english: "HP-UX Security patch : PHSS_25139");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHSS_25139 security update");
 script_set_attribute(attribute: "description", value:
"CDE Base SEP2001 Periodic Patch");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_25139");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHSS_25139");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "HP-UX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/HP-UX/swlist");
 exit(0);
}

include("hpux.inc");
if ( ! hpux_check_ctx ( ctx:"11.11 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_25139 PHSS_25196 PHSS_25788 PHSS_26492 PHSS_27428 PHSS_27872 PHSS_28676 PHSS_29735 PHSS_30011 PHSS_30788 PHSS_32110 PHSS_33325 PHSS_35249 PHSS_36394 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"CDE.CDE-MIN", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDE.CDE-TT", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDE.CDE-SHLIBS", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
