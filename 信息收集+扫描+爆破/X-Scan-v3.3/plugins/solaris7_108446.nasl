#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(23221);
 script_version("$Revision: 1.3 $");

 script_name(english: "Solaris 5.7 (sparc) : 108446-03");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 108446-03");
 script_set_attribute(attribute: "description", value:
'Sun Cluster 2.2: cluster_help/man pages patch.
Date this patch was last updated by Sun : Apr/04/02');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-108446-03-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 108446-03");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"108446-03", obsoleted_by:"", package:"SUNWscch", version:"2.2,REV=1999.02.09.23.30");
e +=  solaris_check_patch(release:"5.7", arch:"sparc", patch:"108446-03", obsoleted_by:"", package:"SUNWscman", version:"2.2,REV=1999.02.09.23.30");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
