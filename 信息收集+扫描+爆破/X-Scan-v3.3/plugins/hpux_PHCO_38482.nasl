
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(38680);
 script_version ("$Revision: 1.2 $");
 script_name(english: "HP-UX Security patch : PHCO_38482");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHCO_38482 security update");
 script_set_attribute(attribute: "description", value:
"11.31 chmod(1M) cumulative patch");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//hp-ux_patches/11.X/PHCO_38482");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHCO_38482");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "HP-UX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/HP-UX/swlist");
 exit(0);
}

include("hpux.inc");
# this patch is no longer a security fix
exit(0);

