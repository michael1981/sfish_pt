
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17557);
 script_version ("$Revision: 1.6 $");
 script_name(english: "HP-UX Security patch : PHSS_31830");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHSS_31830 security update");
 script_set_attribute(attribute: "description", value:
"Webproxy server 2.1 update");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_31830");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHSS_31830");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "HP-UX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/HP-UX/swlist");
 exit(0);
}

include("hpux.inc");
if ( ! hpux_check_ctx ( ctx:"11.04 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_31830 PHSS_32362 PHSS_33074 PHSS_33666 PHSS_34203 PHSS_35111 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"HP_Webproxy.HPWEB-PX-CORE", version:"A.02.10") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
