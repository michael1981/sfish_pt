
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17509);
 script_version ("$Revision: 1.9 $");
 script_name(english: "HP-UX Security patch : PHSS_29892");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHSS_29892 security update");
 script_set_attribute(attribute: "description", value:
"Virtualvault 4.5 IWS Update");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_29892");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHSS_29892");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "HP-UX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/HP-UX/swlist");
 exit(0);
}

include("hpux.inc");
if ( ! hpux_check_ctx ( ctx:"11.04 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_29892 PHSS_30159 PHSS_30647 PHSS_31827 PHSS_32141 PHSS_34171 PHSS_35104 PHSS_35306 PHSS_35458 PHSS_35553 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"VaultTS.VV-IWS", version:"A.04.50") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"VaultTS.VVOS-ADM-RUN", version:"A.04.50") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"VaultTS.VV-CORE-CMN", version:"A.04.50") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
