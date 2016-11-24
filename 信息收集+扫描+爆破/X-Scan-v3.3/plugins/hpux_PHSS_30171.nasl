
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(16495);
 script_version ("$Revision: 1.10 $");
 script_name(english: "HP-UX Security patch : PHSS_30171");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHSS_30171 security update");
 script_set_attribute(attribute: "description", value:
"Xserver cumulative patch");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_30171");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHSS_30171");
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

if ( hpux_patch_installed (patches:"PHSS_30171 PHSS_30502 PHSS_30505 PHSS_30872 PHSS_31252 PHSS_32953 PHSS_32960 PHSS_35253 PHSS_35966 PHSS_36452 PHSS_37971 PHSS_37972 PHSS_39257 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Xserver.OEM-SERVER", version:"B.11.23") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
