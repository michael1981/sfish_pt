#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25040);
 script_version ("$Revision: 1.9 $");

 script_cve_id("CVE-2007-2165");
 script_bugtraq_id(23546);
 script_xref(name:"OSVDB", value:"34602");
 
 script_name(english:"ProFTPD Auth API Multiple Auth Module Authentication Bypass");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to bypass the authentication scheme of the remote FTP
server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ProFTPd.  Due to a bug in the way the
remote server is configured and the way it processes the USER and PASS
commands, it is possible to log into the remote system by supplying
invalid credentials." );
 script_set_attribute(attribute:"see_also", value:"http://bugs.proftpd.org/show_bug.cgi?id=2922" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest (CVS) version of this software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Attempts to bypass FTP authentication";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("DDI_FTP_Any_User_Login.nasl");
 script_require_keys("ftp/proftpd");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if ( ! port ) port = 21;
if ( get_kb_item("ftp/" + port + "/AnyUser") ) exit(0);

if(! get_port_state(port)) exit(0);
banner = get_ftp_banner(port:port);
if ( ! banner || "ProFTPD" >!< banner ) exit(0);

soc = open_sock_tcp(port);
if( ! soc ) exit(0);
#
# Debian ships with proxy,www-data,irc,list,backup. Try 'bin' for good measure as well
#
foreach user (make_list("proxy", "clamav", "bin"))
{
  pass = "*";
  if (ftp_authenticate(socket:soc, user:user, pass:pass))
  {
    listing = NULL;

    port2 = ftp_pasv(socket:soc);
    if (port2)
    {
      soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
      if (soc2)
      {
        send(socket:soc, data:'LIST\r\n');
        listing = ftp_recv_listing(socket:soc2);
        close(soc2);
      }
    }

    info = 'Nessus was able to log in using the credentials "' + user + '/' + pass + '"';
    if (listing)
      info = info + ' and obtain\nthe following listing of the FTP root :\n' + listing;
    else
      info = info + '.\n';

    report = string(
      "\n",
      info
    );
    security_warning(port:port, extra:report);

    break;
  }
}
close(soc);
