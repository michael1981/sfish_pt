
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(22430);
 script_version ("$Revision: 1.4 $");
 script_name(english: "HP-UX Security patch : PHNE_34009");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHNE_34009 security update");
 script_set_attribute(attribute: "description", value:
"J2793B X.25 SX25-HPerf/SYNC-WAN");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//hp-ux_patches/s700_800/11.X/PHNE_34009");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHNE_34009");
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

if ( hpux_patch_installed (patches:"PHNE_34009 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.61") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.25") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"7.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.26") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.27") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.29") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.30") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-32ALIB", version:"8.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.61") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.25") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"7.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.26") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.27") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.29") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.30") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64ALIB", version:"8.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.61") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.25") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"7.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.26") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.27") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.29") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.30") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.COM-64SLIB", version:"8.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.61") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.25") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"7.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.26") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.27") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.29") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.30") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-32ALIB", version:"8.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.61") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.25") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"7.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.26") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.27") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.29") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.30") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.IP-64ALIB", version:"8.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.61") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.25") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"7.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.26") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.27") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.29") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.30") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-32ALIB", version:"8.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.61") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.25") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"7.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.26") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.27") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.29") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.30") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.PA-64ALIB", version:"8.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.61") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.25") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"7.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.26") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.27") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.29") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.30") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-COM", version:"8.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.61") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.25") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"7.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.26") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.27") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.29") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.30") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-IP", version:"8.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-MAN", version:"1.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-MAN", version:"1.22") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-MAN", version:"1.21") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.61") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.25") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"7.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.26") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.27") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.28") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.29") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.30") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.31") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PA", version:"8.33") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PAD", version:"10.35") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-PAD", version:"10.32") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-SAM", version:"11.X/Rev.7.00.06") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-SAM", version:"11.X/Rev.6.31.9") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-HPERF-SAM", version:"11.X/Rev.6.31.13") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SX25-HPerf.SX25-SNMP", version:"A.11.00.ic23") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-32ALIB", version:"5.15") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-32ALIB", version:"5.3") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-32ALIB", version:"3.7") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-32ALIB", version:"4.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-32ALIB", version:"5.6") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-32ALIB", version:"5.7") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-32ALIB", version:"5.8") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-64ALIB", version:"5.15") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-64ALIB", version:"5.3") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-64ALIB", version:"3.7") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-64ALIB", version:"4.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-64ALIB", version:"5.6") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-64ALIB", version:"5.7") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-64ALIB", version:"5.8") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-COM", version:"5.15") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-COM", version:"5.3") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-COM", version:"3.7") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-COM", version:"4.0") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-COM", version:"5.6") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-COM", version:"5.7") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"SYNC-WAN.SYNC-COM", version:"5.8") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
