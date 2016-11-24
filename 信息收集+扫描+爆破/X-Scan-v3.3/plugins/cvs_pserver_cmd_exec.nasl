#  
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11970);
 script_version ("$Revision: 1.9 $");
 script_bugtraq_id(9306);
 script_xref(name:"OSVDB", value:"6429");
 
 script_name(english:"CVS PServer CVSROOT Passwd File Arbitrary Code Execution");
 script_summary(english:"Logs into the remote CVS server and asks the version");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote version control service has a code execution vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "According to its version number, the remote CVS server has an\n",
     "arbitrary code execution vulnerability.  Any user with the ability to\n",
     "write the CVSROOT/passwd file could execute arbitrary code as root."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?b3bb9c46"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to CVS 1.11.11 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_require_ports("Services/cvspserver", 2401);
 script_dependencies("find_service1.nasl", "cvs_pserver_heap_overflow.nasl");

 exit(0);
}

include('global_settings.inc');

port = get_kb_item("Services/cvspserver");
if(!port)port = 2401;
if(!get_port_state(port))exit(0);
version = get_kb_item(string("cvs/", port, "/version"));
if ( ! version ) exit(0);
if(ereg(pattern:".* 1\.([0-9]\.|10\.|11\.([0-9][^0-9]|10)).*", string:version))
     	security_hole(port);
