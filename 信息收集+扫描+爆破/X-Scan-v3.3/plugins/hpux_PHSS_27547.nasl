
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(16791);
 script_version ("$Revision: 1.5 $");
 script_name(english: "HP-UX Security patch : PHSS_27547");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHSS_27547 security update");
 script_set_attribute(attribute: "description", value:
"X OV SIP3.0 web server update");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_27547");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHSS_27547");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "HP-UX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/HP-UX/swlist");
 exit(0);
}

include("hpux.inc");
if ( ! hpux_check_ctx ( ctx:"11.00 11.11 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_27547 PHSS_27668 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"HPOVSIP.OVSIP", version:"B.01.00") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
