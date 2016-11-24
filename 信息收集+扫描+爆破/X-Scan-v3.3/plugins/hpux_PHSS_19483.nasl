
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(16536);
 script_version ("$Revision: 1.6 $");
 script_name(english: "HP-UX Security patch : PHSS_19483");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHSS_19483 security update");
 script_set_attribute(attribute: "description", value:
"CDE Runtime AUG 99 Cumulative Patch");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_19483");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHSS_19483");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "HP-UX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/HP-UX/swlist");
 exit(0);
}

include("hpux.inc");
if ( ! hpux_check_ctx ( ctx:"11.00 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_19483 PHSS_19748 PHSS_20140 PHSS_20716 PHSS_20864 PHSS_22320 PHSS_22341 PHSS_23517 PHSS_23797 PHSS_23800 PHSS_25138 PHSS_25194 PHSS_25787 PHSS_26490 PHSS_27427 PHSS_27869 PHSS_28675 PHSS_29734 PHSS_30010 PHSS_30668 PHSS_32107 PHSS_32539 PHSS_35433 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"CDE.CDE-ENG-A-MSG", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDE.CDE-TT", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDE.CDE-MIN", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDE.CDE-RUN", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDE.CDE-SHLIBS", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDE.CDE-HELP-RUN", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDE.CDE-DTTERM", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDE.CDE-ENG-A-MAN", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CDE.CDE-ENG-A-HELP", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
