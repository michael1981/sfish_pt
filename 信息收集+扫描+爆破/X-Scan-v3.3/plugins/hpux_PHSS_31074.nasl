
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17550);
 script_version ("$Revision: 1.5 $");
 script_name(english: "HP-UX Security patch : PHSS_31074");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHSS_31074 security update");
 script_set_attribute(attribute: "description", value:
"COM B.03.00.00/COM B.03.00.01");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_31074");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHSS_31074");
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

if ( hpux_patch_installed (patches:"PHSS_31074 PHSS_31078 PHSS_32741 PHSS_33040 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Cluster-OM.CM-OM", version:"B.03.00.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-OM.CM-OM", version:"B.03.00.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-OM.CM-OM-AUTH", version:"B.03.00.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-OM.CM-OM-AUTH", version:"B.03.00.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-OM.CM-OM-TOOLS", version:"B.03.00.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-OM.CM-OM-TOOLS", version:"B.03.00.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OPS-Provider-MOF.OPS-PROVIDER", version:"B.03.00.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OPS-Provider-MOF.OPS-PROVIDER", version:"B.03.00.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CM-Provider-MOF.CM-PROVIDER", version:"B.03.00.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CM-Provider-MOF.CM-PROVIDER", version:"B.03.00.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-OM.CM-OM", version:"B.03.00.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-OM.CM-OM", version:"B.03.00.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-OM.CM-OM-AUTH", version:"B.03.00.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-OM.CM-OM-AUTH", version:"B.03.00.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-OM.CM-OM-TOOLS", version:"B.03.00.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-OM.CM-OM-TOOLS", version:"B.03.00.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OPS-Provider-MOF.OPS-PROVIDER", version:"B.03.00.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OPS-Provider-MOF.OPS-PROVIDER", version:"B.03.00.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CM-Provider-MOF.CM-PROVIDER", version:"B.03.00.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"CM-Provider-MOF.CM-PROVIDER", version:"B.03.00.01") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
