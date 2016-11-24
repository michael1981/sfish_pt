
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(22260);
 script_version ("$Revision: 1.9 $");
 script_name(english: "HP-UX Security patch : PHCO_34215");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHCO_34215 security update");
 script_set_attribute(attribute: "description", value:
"libpam_unix cumulative patch");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//superseded_patches/hp-ux_patches/s700_800/11.X/PHCO_34215");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHCO_34215");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "HP-UX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/HP-UX/swlist");
 exit(0);
}

include("hpux.inc");
if ( ! hpux_check_ctx ( ctx:"11.23 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHCO_34215 PHCO_35251 PHCO_35850 PHCO_36759 PHCO_37070 PHCO_37076 PHCO_39230 PHCO_39711 PHCO_40360 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.CORE-ENG-A-MAN", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE2-64SLIB", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE2-SHLIBS", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE2-64SLIB", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE2-SHLIBS", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
