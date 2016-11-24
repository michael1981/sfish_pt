#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(36678);
 script_version("$Revision: 1.1 $");

 script_name(english: "Solaris 5.7 (sparc) : 120651-01");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 120651-01");
 script_set_attribute(attribute: "description", value:
'Sun StorEdge EBS 7.2: Product Patch SU1.
Date this patch was last updated by Sun : Jan/27/06');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-120651-01-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 120651-01");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"120651-01", obsoleted_by:"116832-03 ", package:"SUNWebsc", version:"7.2,REV=172");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"120651-01", obsoleted_by:"116832-03 ", package:"SUNWebsd", version:"7.2,REV=172");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"120651-01", obsoleted_by:"116832-03 ", package:"SUNWebsm", version:"7.2,REV=172");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"120651-01", obsoleted_by:"116832-03 ", package:"SUNWebsn", version:"7.2,REV=172");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"120651-01", obsoleted_by:"116832-03 ", package:"SUNWebss", version:"7.2,REV=172");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
