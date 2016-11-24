
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(16678);
 script_version ("$Revision: 1.7 $");
 script_name(english: "HP-UX Security patch : PHSS_29371");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHSS_29371 security update");
 script_set_attribute(attribute: "description", value:
"X/Motif Runtime Periodic Patch");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_29371");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHSS_29371");
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

if ( hpux_patch_installed (patches:"PHSS_29371 PHSS_30262 PHSS_30787 PHSS_31000 PHSS_33130 PHSS_35711 PHSS_37028 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"X11.X11R5-SHLIBS", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"X11.MOTIF-SHLIB", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"X11.X11R6-SHLIBS", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"X11.X11-FONT-MIN", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"X11.X11-FONT-AUX", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"X11.X11-TCH-B-MSG", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
