#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(23100);
 script_version ("$Revision: 1.8 $");
 script_bugtraq_id(4494);
 name["english"] = "Solaris 2.6 (sparc) : 105458-23";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing Sun Security Patch number 105458-23
(Sun Cluster 2.1: Server/Client software).

Date this patch was last updated by Sun : Wed Aug 13 01:07:43 MDT 2003

You should install this patch for your system to be up-to-date." );
 script_set_attribute(attribute:"solution", value:
"http://sunsolve.sun.com/search/document.do?assetkey=1-21-105458-23-1" );
 script_set_attribute(attribute:"risk_factor", value:"High" );


 script_end_attributes();

 
 summary["english"] = "Check for patch 105458-23"; 
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

e +=  solaris_check_patch(release:"5.6", arch:"sparc", patch:"105458-23", obsoleted_by:"", package:"SUNWsci", version:"2.1,REV=2.1");
e +=  solaris_check_patch(release:"5.6", arch:"sparc", patch:"105458-23", obsoleted_by:"", package:"SUNWsma", version:"2.1,REV=2.1");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
else 
{
	set_kb_item(name:"BID-4494", value:TRUE);
}
