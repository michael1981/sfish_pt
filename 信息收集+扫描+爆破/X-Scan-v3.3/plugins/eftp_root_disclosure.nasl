#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID and CAN
#
# GPL
#
# References:
# Date:  Wed, 12 Sep 2001 04:36:22 -0700 (PDT)
# From: "ByteRage" <byterage@yahoo.com>
# Subject: EFTP Version 2.0.7.337 vulnerabilities
# To: bugtraq@securityfocus.com
# 


include("compat.inc");

if(description)
{
 script_id(11093);
 script_version("$Revision: 1.15 $");

 script_bugtraq_id(3333);
 script_xref(name:"OSVDB", value:"51614");

 script_name(english:"EFTP Nonexistent File Request Installation Directory Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of EFTP installed on the remote host reveals its
installation directory if sent a request for a nonexistent file.  An
authenticated attacker may leverage this flaw to gain more knowledge
about the affected host, such as its filesystem layout." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-09/0100.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.2 or higher, as it has been reported to fix this
vulnerability." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N" );
script_end_attributes();

 
 summary["english"] = "EFTP installation directory disclosure";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/login");
 exit(0);
}

#
include("ftp_func.inc");

cmd[0] = "GET";
cmd[1] = "MDTM";

port = get_kb_item("Services/ftp");
if(!port)port = 21;
login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");
# login = "ftp"; pass = "test@test.com";

if (!login) login = "ftp";
if (!pass) pass = "nessus@nessus.com";

if(! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);

if( ftp_authenticate(socket:soc, user:login, pass:pass))
{
  for (i = 0; i < 2; i=i+1)
  {
    req = string(cmd[i], " nessus", rand(), "\r\n");
    send(socket:soc, data:req);
    r = ftp_recv_line(socket:soc);
    if (egrep(string:r, pattern:" '[A-Za-z]:\\'"))
    {
      security_warning(port);
      ftp_close(socket:soc);
      exit(0);
    }
  }
}
