#
# (C) Tenable Network Security, Inc.
# 


include("compat.inc");


if(description)
{
 script_id(14804);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2004-1546");
 script_bugtraq_id(11238);
 script_xref(name:"OSVDB", value:"10223");
 script_xref(name:"OSVDB", value:"10224");
 
 script_name(english:"MDaemon < 6.5.2 Multiple Remote Buffer Overflows");
 script_summary(english:"Checks the remote version of Mdaemon");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote SMTP server has multiple buffer overflow vulnerabilities."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running Alt-N MDaemon, a SMTP/IMAP server for\n",
     "Windows.\n\n",
     "According to its banner, the version of MDaemon running on the remote\n",
     "host has multiple buffer overflow vulnerabilities.  A remote attacker\n",
     "could exploit these issues to execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-09/0807.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to MDaemon 6.5.2 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"SMTP problems");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#


include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;

banner = get_smtp_banner(port:port);
if ( ! banner ) exit(0);

if ( egrep(pattern:"^220.*ESMTP MDaemon ([0-5][^0-9]|6\.([0-4][^0-9]|5\.[0-1]))", string:banner) ) security_hole(port);
