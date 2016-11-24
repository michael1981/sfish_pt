
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(22433);
 script_version ("$Revision: 1.4 $");
 script_name(english: "HP-UX Security patch : PHNE_34988");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHNE_34988 security update");
 script_set_attribute(attribute: "description", value:
"J2793B X.25 SX25-HPerf/SYNC-WAN");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//hp-ux_patches/s700_800/11.X/PHNE_34988");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHNE_34988");
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

if ( hpux_patch_installed (patches:"PHNE_34988 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-SAM", version:"B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-ALIB", version:"B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-ALIB", version:"B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PAD", version:"B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-ALIB", version:"B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-ALIB", version:"B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-ALIB", version:"B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-ALIB", version:"B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-COM", version:"B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-MAN", version:"B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-SNMP", version:"B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-ALIB", version:"B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-ALIB", version:"B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
