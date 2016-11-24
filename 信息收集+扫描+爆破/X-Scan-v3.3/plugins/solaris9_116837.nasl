#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(25195);
 script_version("$Revision: 1.5 $");

 script_name(english: "Solaris 9 (sparc) : 116837-04");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 116837-04");
 script_set_attribute(attribute: "description", value:
'Sun LDAP C SDK 5.19 patch : SunOS sparc.
Date this patch was last updated by Sun : Feb/06/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-116837-04-1");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Check for patch 116837-04");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"116837-04", obsoleted_by:"", package:"SUNWldk", version:"5.11,REV=2003.05.14.12.06");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"116837-04", obsoleted_by:"", package:"SUNWldkx", version:"5.11,REV=2003.05.14.12.06");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
