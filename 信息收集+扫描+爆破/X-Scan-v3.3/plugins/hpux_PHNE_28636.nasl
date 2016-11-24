
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17417);
 script_version ("$Revision: 1.6 $");
 script_name(english: "HP-UX Security patch : PHNE_28636");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHNE_28636 security update");
 script_set_attribute(attribute: "description", value:
"EISA 100BT cumulative patch");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//hp-ux_patches/s700_800/11.X/PHNE_28636");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHNE_28636");
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

if ( hpux_patch_installed (patches:"PHNE_28636 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"100BT-EISA-KRN.100BT-KRN", version:"B.11.00.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-KRN.100BT-KRN", version:"B.11.00.02") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-KRN.100BT-KRN", version:"B.11.00.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-KRN.100BT-KRN", version:"B.11.00.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-RUN.100BT-RUN", version:"B.11.00.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-RUN.100BT-RUN", version:"B.11.00.02") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-RUN.100BT-RUN", version:"B.11.00.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-RUN.100BT-RUN", version:"B.11.00.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-RUN.100BT-INIT", version:"B.11.00.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-RUN.100BT-INIT", version:"B.11.00.02") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-RUN.100BT-INIT", version:"B.11.00.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-RUN.100BT-INIT", version:"B.11.00.04") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-FMT.100BT-FORMAT", version:"B.11.00.01") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-FMT.100BT-FORMAT", version:"B.11.00.02") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-FMT.100BT-FORMAT", version:"B.11.00.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-FMT.100BT-FORMAT", version:"B.11.00.04") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
