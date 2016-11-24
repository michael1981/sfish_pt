#
# (C) Tenable Network Security, Inc.
#

# A big thanks to Andrew Daviel
#


include("compat.inc");


if(description)
{
 script_id(14819);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-1999-0564", "CVE-2004-2166");
 script_bugtraq_id(11247);
 script_xref(name:"OSVDB", value:"9346");

 script_name(english:"Canon ImageRUNNER SMTP Arbitrary Content Printing");
 script_summary(english:"Determines if the remote host is a Canon ImageRUNNER Printer");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote printer has a denial of service vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host seems to be a Canon ImageRUNNER printer, which runs a\n",
     "SMTP service.\n\n",
     "It is possible to send an email to the SMTP service and have it\n",
     "printed out. An attacker may use this flaw to send an endless stream\n",
     "of emails to the remote device and cause a denial of service by using\n",
     "all of the print paper."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2004-09/0307.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Disable the email printing service via the device's web interface."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P"
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

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

banner = smtp_recv_line(socket:soc);
if ( ! banner ) exit(0);

if ( !ereg(pattern:"^220 .* SMTP Ready.$", string:banner ) ) exit(0);
send(socket:soc, data:'EHLO there\r\n');
r = smtp_recv_line(socket:soc);
if ( ! ereg(pattern:"^550 Command unrecognized", string:banner) ) exit(0);
send(socket:soc, data:'HELO there\r\n');
r = smtp_recv_line(socket:soc);
if ( ! ereg(pattern:"^250 . Hello there \[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\] please to meet you\.", string:banner) ) exit(0);

send(socket:soc, data:'RCPT TO: nessus\r\n');
r = smtp_recv_line(socket:soc);
if ( ! ereg(pattern:"^503 need MAIL From: first\.", string:r) ) exit(0);

send(socket:soc, data:'MAIL FROM: nessus\r\n');
r = smtp_recv_line(socket:soc);
if ( ! ereg(pattern:"^250 nessus\.\.\. Sender Ok", string:r) ) exit(0);
send(socket:soc, data:'RCPT TO: nessus\r\n');
r = smtp_recv_line(socket:soc);
if ( ! ereg(pattern:"^250 nessus\.\.\. Receiver Ok", string:r) ) exit(0);

security_warning(port);
