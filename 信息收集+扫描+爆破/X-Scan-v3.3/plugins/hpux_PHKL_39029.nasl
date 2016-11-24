
#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(36063);
 script_version ("$Revision: 1.2 $");
 script_name(english: "HP-UX Security patch : PHKL_39029");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing HP-UX PHKL_39029 security update");
 script_set_attribute(attribute: "description", value:
"VRTS 4.1 MP2RP2 VRTSodm Kernel Patch");
 script_set_attribute(attribute: "solution", value: "ftp://ftp.itrc.hp.com//hp-ux_patches/s700_800/11.X/PHKL_39029");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Checks for patch PHKL_39029");
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

if ( hpux_patch_installed (patches:"PHKL_39029 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"VRTSodm.ODM-KRN", version:"4.1") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"VRTSodm.ODM-KRN", version:"4.1") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"VRTSodm.ODM-KRN", version:"4.1") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"VRTSodm.ODM-KRN", version:"4.1") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"VRTSodm.ODM-RUN", version:"4.1") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"VRTSodm.ODM-RUN", version:"4.1") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"VRTSodm.ODM-RUN", version:"4.1") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"VRTSodm.ODM-RUN", version:"4.1") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"VRTSodm.ODM-MAN", version:"4.1") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"VRTSodm.ODM-MAN", version:"4.1") )
{
 security_hole(0);
 exit(0);
}
exit(0, "Host is not affected");
