#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(22961);
 script_version("$Revision: 1.22 $");

 script_name(english: "Solaris 5.10 (sparc) : 120189-19");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 120189-19");
 script_set_attribute(attribute: "description", value:
'StarSuite 8 (Solaris): Update 14.
Date this patch was last updated by Sun : Sep/09/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-120189-19-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 120189-19");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-base", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-calc", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-core01", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-core02", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-core03", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-core04", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-core05", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-core06", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-core07", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-core08", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-core09", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-draw", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-gnome-integration", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-graphicfilter", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-impress", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-ja-fonts", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-ja-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-ja-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-ja", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-javafilter", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-ko-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-ko-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-ko", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-lngutils", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-math", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-onlineupdate", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-sunsearchtoolbar", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-w4wfilter", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-writer", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-xsltfilter", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-zh-CN-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-zh-CN-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-zh-CN", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-zh-TW-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-zh-TW-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120189-19", obsoleted_by:"", package:"SUNWstarsuite-zh-TW", version:"8.0.0,REV=106.2005.05.26");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
