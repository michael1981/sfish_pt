#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10652);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-1999-0243", "CVE-1999-0708", "CVE-2001-0609");
 script_bugtraq_id(2576, 651);
 script_xref(name:"OSVDB", value:"1078");
 script_xref(name:"OSVDB", value:"541");
 script_xref(name:"OSVDB", value:"540");

 script_name(english:"cfingerd < 1.4.4 Multiple Vulnerabilities");
 script_summary(english:"Checks the cfinger version");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote finger service has multiple vulnerabilities."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The version of cfingerd running on the remote host has multiple\n",
     "vulnerabilities, including :\n\n",
     "  - A local buffer overflow in the GECOS field, which can be used to\n",
     "    escalate privileges.\n",
     "  - A format string vulnerability, triggered by a malformed ident\n",
     "    reply.  This can be used to execute arbitrary code.\n",
     "  - A local privilege escalation issue."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/1999-q3/1007.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/vendor/2001-q2/0009.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to cfingerd version 1.4.4 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Finger abuses"); 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", 
 		     "cfinger_version.nasl");
 script_require_keys("cfingerd/version");
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/finger");
if(!port)port = 79;

version = get_kb_item("cfingerd/version");
if(version)
{
 if(ereg(pattern:"[0-1]\.(([0-3]\.[0-9]*)|(4\.[0-3]))",
 	string:version))security_hole(port);
}
