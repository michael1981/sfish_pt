
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17482);
 script_version ("$Revision: 1.6 $");
 script_name(english: "HP-UX Security patch : PHSS_27639");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHSS_27639 security update");
 script_set_attribute(attribute: "description", value:
"X OV NNM6.2 http server fix");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_27639");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHSS_27639");
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

if ( hpux_patch_installed (patches:"PHSS_27639 PHSS_27747 PHSS_27836 PHSS_27917 PHSS_28092 PHSS_28095 PHSS_28258 PHSS_28348 PHSS_28400 PHSS_28473 PHSS_28546 PHSS_28587 PHSS_28705 PHSS_28878 PHSS_29206 PHSS_29429 PHSS_29754 PHSS_30104 PHSS_30419 PHSS_31185 PHSS_32046 PHSS_32690 PHSS_33287 PHSS_34008 PHSS_35113 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OVPlatform.OVWWW-SRV", version:"B.06.20.00") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
