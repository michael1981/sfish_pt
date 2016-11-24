#
# (C) Tenable Network Security, Inc.
# 


include("compat.inc");

if(description)
{
 script_id(15823);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2004-2504");
 script_bugtraq_id(11736);
 script_xref(name:"OSVDB", value:"12158");
 
 script_name(english:"MDaemon File Creation Local Privilege Escalation");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is prone to a local privilege escalation
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Alt-N MDaemon, an SMTP/IMAP server for the
Windows operating system family. 

It is reported that versions up to and including 7.2.0 are prone to
local privilege escalation vulnerability. 

An local attacker may increase his privilege and execute code with
SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-11/1324.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-11/1353.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MDaemon 7.2.1 or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 script_summary(english:"Checks the remote version of Mdaemon");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("find_service2.nasl");
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

if ( egrep(pattern:"^220.*ESMTP MDaemon ([0-6]\..*|7\.([0-1]\..*|2\.0.*))", string:banner) ) security_hole(port);
