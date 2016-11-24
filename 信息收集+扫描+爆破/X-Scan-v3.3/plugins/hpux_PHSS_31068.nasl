
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(16763);
 script_version ("$Revision: 1.6 $");
 script_name(english: "HP-UX Security patch : PHSS_31068");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHSS_31068 security update");
 script_set_attribute(attribute: "description", value:
"MC/ServiceGuard A.11.15.00");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//patches_with_warnings/hp-ux_patches/s700_800/11.X/PHSS_31068");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHSS_31068");
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

if ( hpux_patch_installed (patches:"PHSS_31068 PHSS_32244 PHSS_32661 PHSS_32728 PHSS_34506 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Cluster-Monitor.CM-CORE", version:"A.11.15.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-Monitor.CM-CORE-COM", version:"A.11.15.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Package-Manager.CM-PKG", version:"A.11.15.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-Monitor.CM-CORE-MAN", version:"A.11.15.00") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
