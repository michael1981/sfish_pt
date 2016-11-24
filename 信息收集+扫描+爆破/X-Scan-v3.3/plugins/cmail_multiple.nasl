#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15828);
 script_cve_id("CVE-2004-1128", "CVE-2004-1129", "CVE-2004-1130");
 script_bugtraq_id(11742);
 script_xref(name:"OSVDB", value:"12130");
 script_xref(name:"OSVDB", value:"12131");
 script_xref(name:"OSVDB", value:"12132");
 script_xref(name:"OSVDB", value:"12133");
 script_xref(name:"Secunia", value:"13298");

 script_version ("$Revision: 1.9 $");
 script_name(english:"Youngzsoft CMailServer < 5.2.1 Multiple Remote Vulnerabilities");
 script_summary(english:"Detects the version of CMail");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote mail server has multiple vulnerabilities."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running YoungZSoft CMailServer, a mail server\n",
     "for Microsoft Windows.\n\n",
     "The version of CMailServer running on the remote machine has multiple\n",
     "vulnerabilities, including buffer overflow, SQL injection, and HTML\n",
     "injection.  These vulnerabilities could allow a remote attacker to\n",
     "execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2004-11/0329.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to CMailServer 5.2.1 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"SMTP problems");
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/cmailserver-smtp");
 exit(0);
}

#
# The script code starts here
#
include("smtp_func.inc");
port = get_kb_item("Services/cmailserver-smtp");
if ( ! port ) exit(0);
banner = get_smtp_banner ( port:port);
if ( egrep(pattern:"^220 ESMTP CMailServer ([0-4]\..*|5\.([0-1]\..*|2\.0.*))SMTP Service Ready", string:banner) )
{
	security_hole ( port );
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}

