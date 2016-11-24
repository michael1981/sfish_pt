
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(16824);
 script_version ("$Revision: 1.5 $");
 script_name(english: "HP-UX Security patch : PHSS_22540");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHSS_22540 security update");
 script_set_attribute(attribute: "description", value:
"X  MC/ServiceGuard and SG-OPS Edition A.11.09");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_22540");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHSS_22540");
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

if ( hpux_patch_installed (patches:"PHSS_22540 PHSS_22683 PHSS_22876 PHSS_23511 PHSS_24033 PHSS_24536 PHSS_24850 PHSS_25499 PHSS_25935 PHSS_26338 PHSS_26750 PHSS_27158 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"DLM.CM-DLM", version:"A.11.09") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DLM.CM-DLM-CMDS", version:"A.11.09") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DLM-Clust-Mon.CM-CORE", version:"A.11.09") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-Monitor.CM-CORE", version:"A.11.09") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"DLM-Pkg-Mgr.CM-PKG", version:"A.11.09") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Package-Manager.CM-PKG", version:"A.11.09") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CM-Provider-MOF.CM-MOF", version:"A.11.09") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CM-Provider-MOF.CM-PROVIDER", version:"A.11.09") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"ATS-CORE.ATS-RUN", version:"A.11.09") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
