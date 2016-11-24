
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(33190);
 script_version ("$Revision: 1.5 $");
 script_name(english: "HP-UX Security patch : PHSS_38009");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHSS_38009 security update");
 script_set_attribute(attribute: "description", value:
"X  OV NNM8.01 NNM 8.0x Patch 8.02.001");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_38009");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHSS_38009");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "HP-UX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/HP-UX/swlist");
 exit(0);
}

include("hpux.inc");
if ( ! hpux_check_ctx ( ctx:"11.23 11.31 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_38009 PHSS_38435 PHSS_38609 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"HPOvNNM.HPOVSTPLR", version:"2.02.070") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"HPOvNNM.HPOVNMSEMBDDB", version:"2.02.074") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"HPOvNNM.HPOVNMSCOMMON", version:"2.02.070") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"HPOvNNM.HPOVNNMGEN", version:"2.02.070") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"HPOvNNM.HPOVNNMINSTALL", version:"2.02.070") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"HPOvNNM.HPOVNMSCAUSESV", version:"2.02.070") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"HPOvNNM.HPOVNMSEVNT", version:"2.02.073") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"HPOvNNM.HPOVNMSSNMPCO", version:"2.02.070") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"HPOvNNM.HPOVNMSEVTPSV", version:"2.02.070") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"HPOvNNM.HPNMSCOMPS", version:"2.02.050") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"HPOvNNM.HPOVSNMP", version:"2.02.074") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"HPOvNNM.HPOVNNMUI", version:"2.02.070") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"HPOvNNM.HPOVNMSSPMD", version:"2.02.074") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"HPOvNNM.HPOVNMSLIC", version:"2.02.070") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"HPOvNNM.HPOVNMSDISCOSV", version:"2.02.070") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
