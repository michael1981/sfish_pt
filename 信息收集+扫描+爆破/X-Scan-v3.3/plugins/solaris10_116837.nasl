#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(25194);
 script_version ("$Revision: 1.6 $");
 name["english"] = "Solaris 10 (sparc) : 116837-03";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Sun Security Patch number 116837-03
(Sun LDAP C SDK 5.18 patch : SunOS sparc).

Date this patch was last updated by Sun : Fri Feb 06 04:58:02 MST 2009

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-116837-03-1" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_end_attributes();

 
 summary["english"] = "Check for patch 116837-03"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"116837-03", obsoleted_by:"OBSOLETE", package:"SUNWldk", version:"5.11,REV=2003.05.14.12.06");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"116837-03", obsoleted_by:"OBSOLETE", package:"SUNWldkx", version:"5.11,REV=2003.05.14.12.06");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
