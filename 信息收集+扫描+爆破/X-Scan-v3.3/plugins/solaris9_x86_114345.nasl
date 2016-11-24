#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(15758);
 script_version ("$Revision: 1.15 $");
 name["english"] = "Solaris 9 (i386) : 114345-08";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Sun Security Patch number 114345-08
(arp, dlcosmk, ip, and ipgpc Patch).

Date this patch was last updated by Sun : Wed Jan 26 03:35:13 MST 2005

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-114345-08-1" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_end_attributes();

 
 summary["english"] = "Check for patch 114345-08"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114345-08", obsoleted_by:"117172-17", package:"SUNWcsr", version:"11.9.0,REV=2002.11.04.02.51");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114345-08", obsoleted_by:"117172-17", package:"SUNWhea", version:"11.9.0,REV=2002.11.04.02.51");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114345-08", obsoleted_by:"117172-17", package:"SUNWqos", version:"11.9.0,REV=2002.11.04.02.51");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
