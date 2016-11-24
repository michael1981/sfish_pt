
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(16900);
 script_version ("$Revision: 1.7 $");
 script_name(english: "HP-UX Security patch : PHKL_26233");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHKL_26233 security update");
 script_set_attribute(attribute: "description", value:
"VM-JFS ddlock, mmap,thread perf, user limits");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//superseded_patches/hp-ux_patches/s700_800/11.X/PHKL_26233");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHKL_26233");
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

if ( hpux_patch_installed (patches:"PHKL_26233 PHKL_27278 PHKL_28267 PHKL_28428 PHKL_28990 PHKL_30158 PHKL_30616 PHKL_31003 PHKL_32578 PHKL_32806 PHKL_33261 PHKL_33270 PHKL_33988 PHKL_35464 PHKL_35564 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.CORE2-KRN", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE2-KRN", version:"B.11.11") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
