#
# This script was written by H D Moore <hdmoore@digitaldefense.net>
# See the Nessus Scripts License for details
#
#
# Improved by John Lampe to see if XEXCH is an allowed verb


include("compat.inc");

if(description)
{
     script_id(11889);
     script_bugtraq_id(8838);
     script_cve_id("CVE-2003-0714");
     script_xref(name:"IAVA", value:"2003-A-0031");
     script_xref(name:"IAVA", value:"2003-a-0016");
     script_xref(name:"OSVDB", value:"2674");
     script_version("$Revision: 1.14 $");
     name["english"] = "Exchange XEXCH50 Remote Buffer Overflow";
     script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is prone to a buffer overflow or denial of
service attack." );
 script_set_attribute(attribute:"description", value:
"The remote mail server appears to be running a version of the
Microsoft Exchange SMTP service that is vulnerable to a flaw in the
XEXCH50 extended verb.  This flaw can be used to completely crash
Exchange 5.5 or to execute arbitrary code on Exchange 2000." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-10/0215.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/bulletin/MS03-046.mspx" );
 script_set_attribute(attribute:"solution", value:
"Apply the one of the workarounds listed in the vendor's advisory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


    summary["english"] = "Tests to see if authentication is required for the XEXCH50 command";
    script_summary(english:summary["english"]);
 
    script_category(ACT_GATHER_INFO);
 
    script_copyright(english:"This script is Copyright (C) 2003-2009 Digital Defense Inc.");
 
    family["english"] = "SMTP problems";
    script_family(english:family["english"]);
    
    script_dependencies("smtpserver_detect.nasl");
    script_exclude_keys("SMTP/wrapped");
    script_require_ports("Services/smtp", 25);
    exit(0);
}

include("global_settings.inc");
include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if(! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);


greeting = smtp_recv_banner(socket:soc);
if(debug_level) display("GREETING: ", greeting, "\n");

# look for the exchange banner, removing this may get us through some proxies
if (! egrep(string:greeting, pattern:"microsoft", icase:TRUE)) exit(0);

send(socket:soc, data:string("EHLO X\r\n"));
ok = smtp_recv_line(socket:soc);
if (! ok) exit(0);
if(debug_level) display("HELO: ", ok, "\n");
if("XEXCH50" >!< ok)exit(0);

send(socket:soc, data:string("MAIL FROM: Administrator\r\n"));
ok = smtp_recv_line(socket:soc);
if (! ok) exit(0);
if(debug_level) display("MAIL: ", ok, "\n");

send(socket:soc, data:string("RCPT TO: Administrator\r\n"));
ok = smtp_recv_line(socket:soc);
if (! ok) exit(0);
if(debug_level) display("RCPT: ", ok, "\n");

send(socket:soc, data:string("XEXCH50 2 2\r\n"));
ok = smtp_recv_line(socket:soc);
if (! ok) exit(0);
if(debug_level) display("XEXCH50: ", ok, "\n");

if (egrep(string:ok, pattern:"^354 Send binary")) security_hole(port:port);

close(soc);
