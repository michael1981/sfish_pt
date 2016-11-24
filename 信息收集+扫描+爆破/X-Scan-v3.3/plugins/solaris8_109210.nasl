#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(23307);
 script_version("$Revision: 1.7 $");

 script_name(english: "Solaris 5.8 (sparc) : 109210-19");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 109210-19");
 script_set_attribute(attribute: "description", value:
'Sun Cluster 2.2: Framework/Comm Patch.
Date this patch was last updated by Sun : Feb/13/04');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-109210-19-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 109210-19");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWccd", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWcmm", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWcsnmp", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWff", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWffx", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWmond", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWmondx", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWpnm", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWsc", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWsccf", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWsci", version:"2.2,REV=2000.02.29.15.49");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWscid", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWscins", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWsclb", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWsclbx", version:"2.2,REV=2000.03.14.18.21");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"109210-19", obsoleted_by:"", package:"SUNWsma", version:"2.2,REV=2000.03.14.18.21");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
