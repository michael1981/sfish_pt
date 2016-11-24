#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(18097);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2005-0753");
 script_bugtraq_id(13217);
 script_xref(name:"OSVDB", value:"15670");

 script_name(english:"CVS < 1.11.20 / 1.12.12 Multiple Unspecified Vulnerabilities");
 script_summary(english:"Logs into the remote CVS server and asks the version");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote version control service has multiple vulnerabilities."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "According to its version number, the remote CVS server has unspecified\n",
     "vulnerabilities.  This includes a double free, and a buffer overflow.\n",
     "A remote attacker could exploit these to crash the server, or possibly\n",
     "execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?3d5ca22d"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to CVS 1.12.12 / 1.11.20 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");

 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_require_ports("Services/cvspserver", 2401);
 script_dependencies("cvs_double_free.nasl");

 exit(0);
}

include('global_settings.inc');
port = get_kb_item("Services/cvspserver");
if(!port)port = 2401;
if(!get_port_state(port))exit(0);

version = get_kb_item(string("cvs/", port, "/version"));

if (  ! version ) exit(0);
if(ereg(pattern:".* 1\.([0-9]\.|10\.|11\.([0-9][^0-9]|1[0-9][^0-9])|12\.([0-9][^0-9]|1[0-1][^0-9])).*", string:version)) security_hole(port);
