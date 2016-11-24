#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11570);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2002-1539");
 script_bugtraq_id(6053);
 script_xref(name:"OSVDB", value:"12047");
 
 script_name(english:"MDaemon POP Server Multiple Command Remote Overflow DoS");
 script_summary(english:"Determines the version number of the remote POP server");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote POP server has a denial of service vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "According to its banner, the remote POP server has a denial of\n",
     "service vulnerability.  Input to the DELE and UIDL commands\n",
     "are not properly handled.  A remote, authenticated attacker could\n",
     "exploit this to crash the POP service."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2003-04/0353.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to MDaemon 6.5.0 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "sendmail_expn.nasl");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#


include("pop3_func.inc");
port = get_kb_item("Services/pop3");
if(!port)port = 110;
banner  = get_pop3_banner( port : port );
if ( ! banner ) exit(0);
if(ereg(pattern:"POP MDaemon ([0-5]\.|6\.[0-4]\.)", string:banner))
 	security_warning(port);
