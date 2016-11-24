
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(16706);
 script_version ("$Revision: 1.5 $");
 script_name(english: "HP-UX Security patch : PHSS_29120");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHSS_29120 security update");
 script_set_attribute(attribute: "description", value:
"X MC/ServiceGuard and SG-OPS Edition A.11.13");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//patches_with_warnings/hp-ux_patches/s700_800/11.X/PHSS_29120");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHSS_29120");
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

if ( hpux_patch_installed (patches:"PHSS_29120 PHSS_30742 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"DLM-Pkg-Mgr.CM-PKG", version:"A.11.13") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Package-Manager.CM-PKG", version:"A.11.13") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DLM-Pkg-Mgr.CM-PKG-MAN", version:"A.11.13") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Package-Manager.CM-PKG-MAN", version:"A.11.13") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DLM-Prov-MOF.CM-MOF", version:"A.11.13") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CM-Provider-MOF.CM-MOF", version:"A.11.13") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DLM-Prov-MOF.CM-PROVIDER", version:"A.11.13") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CM-Provider-MOF.CM-PROVIDER", version:"A.11.13") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DLM-ATS-Core.ATS-MAN", version:"A.11.13") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"ATS-CORE.ATS-MAN", version:"A.11.13") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DLM-ATS-Core.ATS-RUN", version:"A.11.13") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"ATS-CORE.ATS-RUN", version:"A.11.13") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DLM-NMAPI.CM-NMAPI", version:"A.11.13") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DLM-Clust-Mon.CM-CORE", version:"A.11.13") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-Monitor.CM-CORE", version:"A.11.13") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DLM-Clust-Mon.CM-CORE-MAN", version:"A.11.13") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-Monitor.CM-CORE-MAN", version:"A.11.13") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
