
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(32158);
 script_version ("$Revision: 1.2 $");
 script_name(english: "HP-UX Security patch : PHSS_37704");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHSS_37704 security update");
 script_set_attribute(attribute: "description", value:
"11.31  HP WBEM Services A.02.05.08");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//hp-ux_patches/11.X/PHSS_37704");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHSS_37704");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "HP-UX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/HP-UX/swlist");
 exit(0);
}

include("hpux.inc");
if ( ! hpux_check_ctx ( ctx:"11.31 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_37704 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"WBEMServices.WBEM-CORE-COM", version:"A.02.05.08") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"WBEMServices.WBEM-MAN", version:"A.02.05.08") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"WBEMServices.WBEM-CORE", version:"A.02.05.08") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"WBEMServices.WBEM-CORE", version:"A.02.05.08") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
