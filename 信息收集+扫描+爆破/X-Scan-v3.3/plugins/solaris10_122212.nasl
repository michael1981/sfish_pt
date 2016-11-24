#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(22970);
 script_version("$Revision: 1.27 $");

 script_name(english: "Solaris 10 (sparc) : 122212-34");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 122212-34");
 script_set_attribute(attribute: "description", value:
'GNOME 2.6.0: GNOME Desktop Patch.
Date this patch was last updated by Sun : Oct/08/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-122212-34-1");
 script_set_attribute(attribute: "risk_factor", value: "High");
 script_end_attributes();

 script_summary(english: "Check for patch 122212-34");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWPython", version:"2.3.3,REV=10.0.3.2004.12.15.14.07");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWgnome-desktop-prefs-share", version:"2.6.0,REV=10.0.3.2004.12.21.13.18");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWgnome-desktop-prefs", version:"2.6.0,REV=10.0.3.2004.12.21.13.18");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWgnome-display-mgr-root", version:"2.6.0,REV=10.0.3.2004.12.15.21.16");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWgnome-display-mgr-share", version:"2.6.0,REV=10.0.3.2004.12.15.21.16");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWgnome-display-mgr", version:"2.6.0,REV=10.0.3.2004.12.15.21.16");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWgnome-file-mgr-root", version:"2.6.0,REV=10.0.3.2004.12.15.19.24");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWgnome-file-mgr-share", version:"2.6.0,REV=10.0.3.2004.12.15.19.24");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWgnome-file-mgr", version:"2.6.0,REV=10.0.3.2004.12.15.19.24");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWgnome-img-editor-share", version:"2.6.0,REV=10.0.3.2004.12.16.17.35");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWgnome-img-editor", version:"2.6.0,REV=10.0.3.2004.12.16.17.35");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWgnome-img-viewer-share", version:"2.6.0,REV=10.0.3.2004.12.15.23.40");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWgnome-libs-root", version:"2.6.0,REV=10.0.3.2004.12.15.17.32");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWgnome-libs-share", version:"2.6.0,REV=10.0.3.2004.12.15.17.32");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWgnome-libs", version:"2.6.0,REV=10.0.3.2004.12.15.17.32");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWgnome-panel-devel", version:"2.6.0,REV=10.0.3.2004.12.15.19.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWgnome-panel-root", version:"2.6.0,REV=10.0.3.2004.12.15.19.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWgnome-panel-share", version:"2.6.0,REV=10.0.3.2004.12.15.19.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWgnome-panel", version:"2.6.0,REV=10.0.3.2004.12.15.19.13");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWgnome-session-share", version:"2.6.0,REV=10.0.3.2004.12.21.13.03");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWgnome-session", version:"2.6.0,REV=10.0.3.2004.12.21.13.03");
e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-34", obsoleted_by:"", package:"SUNWgnome-themes-share", version:"2.6.0,REV=10.0.3.2004.12.15.17.42");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
