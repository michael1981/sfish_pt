
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(38969);
 script_version ("$Revision: 1.8 $");
 script_name(english: "HP-UX Security patch : PHSS_36311");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHSS_36311 security update");
 script_set_attribute(attribute: "description", value:
"11.31 Aries cumulative patch");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//superseded_patches/hp-ux_patches/11.X/PHSS_36311");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHSS_36311");
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

if ( hpux_patch_installed (patches:"PHSS_36311 PHSS_36520 PHSS_37553 PHSS_38527 PHSS_39294 PHSS_39898 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.CORE2-64SLIB", version:"B.11.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE2-SHLIBS", version:"B.11.31") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
