#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(35209);
 script_version("$Revision: 1.4 $");

 script_name(english: "Solaris 5.10 (x86) : 138687-03");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 138687-03");
 script_set_attribute(attribute: "description", value:
'Portal Server 7.2 Solaris_x86:Maintenance Patch.
Date this patch was last updated by Sun : Jun/30/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-138687-03-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 138687-03");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138687-03", obsoleted_by:"", package:"SUNWportal-admin", version:"7.2,REV=2008.05.03.08.40");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138687-03", obsoleted_by:"", package:"SUNWportal-base", version:"7.2,REV=2008.05.03.08.37");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138687-03", obsoleted_by:"", package:"SUNWportal-portlets", version:"7.2,REV=2008.05.03.08.40");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138687-03", obsoleted_by:"", package:"SUNWportal-search", version:"7.2,REV=2008.05.03.08.39");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138687-03", obsoleted_by:"", package:"SUNWportal-sracommon", version:"7.2,REV=2008.05.03.08.41");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138687-03", obsoleted_by:"", package:"SUNWportal-sracore", version:"7.2,REV=2008.05.03.08.40");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138687-03", obsoleted_by:"", package:"SUNWportal-sragateway", version:"7.2,REV=2008.05.03.08.41");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138687-03", obsoleted_by:"", package:"SUNWportal-sranetletproxy", version:"7.2,REV=2008.05.03.08.41");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"138687-03", obsoleted_by:"", package:"SUNWportal-srarewriterproxy", version:"7.2,REV=2008.05.03.08.41");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
