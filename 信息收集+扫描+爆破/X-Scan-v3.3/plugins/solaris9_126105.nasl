#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(27024);
 script_version("$Revision: 1.21 $");

 script_name(english: "Solaris 5.9 (sparc) : 126105-35");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 126105-35");
 script_set_attribute(attribute: "description", value:
'Sun Cluster 3.2: CORE patch for Solaris 9.
Date this patch was last updated by Sun : Sep/21/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-126105-35-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 126105-35");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWccon", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWcvm", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWcvmr", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWsccomu", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWsccomzu", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWscderby", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWscdev", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWscgds", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWscmasa", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWscmasar", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWscmasasen", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWscmasau", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWscmautil", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWscmd", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWscr", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWscrif", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWscrtlh", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWscsam", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWscspmu", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWscssv", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWsctelemetry", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWscu", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWscucm", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWsczu", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWudlm", version:"3.2.0,REV=2006.12.05.22.50");
e +=  solaris_check_patch(release:"5.9", arch:"sparc", patch:"126105-35", obsoleted_by:"", package:"SUNWudlmr", version:"3.2.0,REV=2006.12.05.22.50");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
