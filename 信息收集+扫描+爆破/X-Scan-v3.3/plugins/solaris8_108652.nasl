#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(23300);
 script_version("$Revision: 1.18 $");

 script_name(english: "Solaris 8 (sparc) : 108652-98");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 108652-98");
 script_set_attribute(attribute: "description", value:
'X11 6.4.1: Xsun patch.
Date this patch was last updated by Sun : May/04/06');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-108652-98-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 108652-98");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108652-98", obsoleted_by:"119067-01 ", package:"SUNWxwacx", version:"6.4.1.3800,REV=0.1999.12.15");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108652-98", obsoleted_by:"119067-01 ", package:"SUNWxwdxm", version:"6.4.1.3800,REV=0.1999.12.15");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108652-98", obsoleted_by:"119067-01 ", package:"SUNWxwfa", version:"6.4.1.3800,REV=0.1999.12.15");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108652-98", obsoleted_by:"119067-01 ", package:"SUNWxwfnt", version:"6.4.1.3800,REV=0.1999.12.15");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108652-98", obsoleted_by:"119067-01 ", package:"SUNWxwice", version:"6.4.1.3800,REV=0.1999.12.15");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108652-98", obsoleted_by:"119067-01 ", package:"SUNWxwicx", version:"6.4.1.3800,REV=0.1999.12.15");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108652-98", obsoleted_by:"119067-01 ", package:"SUNWxwinc", version:"6.4.1.3800,REV=0.1999.12.15");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108652-98", obsoleted_by:"119067-01 ", package:"SUNWxwman", version:"6.4.1.3800,REV=0.1999.12.15");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108652-98", obsoleted_by:"119067-01 ", package:"SUNWxwplt", version:"6.4.1.3800,REV=0.1999.12.15");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108652-98", obsoleted_by:"119067-01 ", package:"SUNWxwplx", version:"6.4.1.3800,REV=0.1999.12.15");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108652-98", obsoleted_by:"119067-01 ", package:"SUNWxwpmn", version:"6.4.1.3800,REV=0.1999.12.15");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"108652-98", obsoleted_by:"119067-01 ", package:"SUNWxwslb", version:"6.4.1.3800,REV=0.1999.12.15");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
