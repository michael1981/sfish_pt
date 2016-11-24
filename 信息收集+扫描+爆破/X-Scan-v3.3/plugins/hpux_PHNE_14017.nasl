
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(16850);
 script_version ("$Revision: 1.5 $");
 script_name(english: "HP-UX Security patch : PHNE_14017");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHNE_14017 security update");
 script_set_attribute(attribute: "description", value:
"cumulative ARPA Transport patch");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//superseded_patches/hp-ux_patches/s700_800/11.X/PHNE_14017");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHNE_14017");
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

if ( hpux_patch_installed (patches:"PHNE_14017 PHNE_14279 PHNE_14702 PHNE_15047 PHNE_15583 PHNE_15692 PHNE_15995 PHNE_16283 PHNE_16645 PHNE_17017 PHNE_17446 PHNE_17662 PHNE_18554 PHNE_18611 PHNE_18708 PHNE_19110 PHNE_19375 PHNE_19899 PHNE_20436 PHNE_20735 PHNE_21767 PHNE_22397 PHNE_23456 PHNE_24715 PHNE_25423 PHNE_26771 PHNE_27886 PHNE_28538 PHNE_29473 PHNE_32041 PHNE_33395 PHNE_35729 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.CORE2-KRN", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.NET2-KRN", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE2-KRN", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Networking.NET2-KRN", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
