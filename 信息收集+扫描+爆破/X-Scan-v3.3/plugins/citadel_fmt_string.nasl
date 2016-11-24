#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15942);

 script_cve_id("CVE-2004-1192");
 script_bugtraq_id(11885);
 script_xref(name:"OSVDB", value:"12344");
 script_xref(name:"Secunia", value:"13425");

 script_version("$Revision: 1.6 $");

 script_name(english:"Citadel/UX lprintf() Function Remote Format String");
 script_summary(english:"Checks the version of the remote Citadel server");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote BBS server has a format string vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running Citadel/UX, a messaging server for Unix.\n\n",
     "There is a format string issue in the remote version of this software.\n",
     "A remote attacker could use this to crash the service, or execute\n",
     "arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2004-12/0113.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2004-12/0139.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Citadel 6.28 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 
 script_dependencies("citadel_overflow.nasl");
 script_require_ports("Services/citadel/ux", 504);
 exit(0);
}


port = get_kb_item("Services/citadel/ux");
if ( ! port ) port = 504;

kb = get_kb_item("citadel/" + port + "/version");
if ( ! kb ) exit(0);


version = egrep(pattern:"^Citadel(/UX)? ([0-5]\..*|6\.([0-1][0-9]|2[0-7])[^0-9])", string:kb);

if ( version )
	security_hole(port);

