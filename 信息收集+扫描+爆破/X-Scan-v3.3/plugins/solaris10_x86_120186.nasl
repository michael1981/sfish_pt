#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(22993);
 script_version("$Revision: 1.21 $");

 script_name(english: "Solaris 5.10 (x86) : 120186-19");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 120186-19");
 script_set_attribute(attribute: "description", value:
'StarOffice 8 (Solaris_x86): Update 14.
Date this patch was last updated by Sun : Sep/10/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-120186-19-1");
 script_set_attribute(attribute: "risk_factor", value: "Medium");
 script_end_attributes();

 script_summary(english: "Check for patch 120186-19");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-base", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-calc", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-core01", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-core02", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-core03", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-core04", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-core05", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-core06", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-core07", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-core08", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-core09", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-de-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-de-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-de", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-draw", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-es-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-es-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-es", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-fr-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-fr-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-fr", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-gnome-integration", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-graphicfilter", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-hu-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-hu-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-hu", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-impress", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-it-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-it-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-it", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-javafilter", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-lngutils", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-math", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-nl-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-nl-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-nl", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-onlineupdate", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-pl-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-pl-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-pl", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-pt-BR-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-pt-BR-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-pt-BR", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-pt-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-pt-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-pt", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-ru-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-ru-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-ru", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-sunsearchtoolbar", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-sv-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-sv-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-sv", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-writer", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120186-19", obsoleted_by:"", package:"SUNWstaroffice-xsltfilter", version:"8.0.0,REV=106.2005.05.26");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_warning(0);
	else  
	   security_warning(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
