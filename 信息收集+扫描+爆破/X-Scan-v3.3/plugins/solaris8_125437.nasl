#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(27010);
 script_version("$Revision: 1.10 $");

 script_name(english: "Solaris 5.8 (sparc) : 125437-17");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 125437-17");
 script_set_attribute(attribute: "description", value:
'Sun Java(TM) System Web Server 7.0U6 Solaris: Update Release patch.
Date this patch was last updated by Sun : Sep/10/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-125437-17-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 125437-17");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"125437-17", obsoleted_by:"", package:"SUNWwbsvr7-cli", version:"7.0,REV=2006.12.04.11.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"125437-17", obsoleted_by:"", package:"SUNWwbsvr7-dev", version:"7.0,REV=2006.12.04.11.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"125437-17", obsoleted_by:"", package:"SUNWwbsvr7", version:"7.0,REV=2006.12.04.11.12");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"125437-17", obsoleted_by:"", package:"SUNWwbsvr7x", version:"7.0,REV=2006.12.04.11.36");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
