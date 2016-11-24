#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(42259);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2002-1661");
 script_bugtraq_id(6490);
 script_xref(name:"OSVDB", value:"16568");

 script_name(english:"leafnode Cross-Posted Article Group Name Prefix DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote NNTP server is vulnerable to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote Leafnode NNTP server is
vulnerable to a denial of service attack.  Specifically, it may go
into an infinite loop with 100% CPU use when an article that has been
crossposted to several groups, one of which is the prefix of another,
and when this article is then requested by its Message-ID. 

Note that Nessus did not actually test for the flaw but instead has
relied upon the version in Leafnode's banner so this may be a false
positive.");
 script_set_attribute(attribute:"see_also", value: "http://leafnode.sourceforge.net/leafnode-SA-2002-01.txt");
 script_set_attribute(attribute:"solution", value: "Upgrade to 1.9.48 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
 script_end_attributes();

 script_summary(english:"Check Leafnode version number for flaws");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("nntpserver_detect.nasl");
 script_require_ports("Services/nntp", 119);
 script_require_keys("nntp/leafnode");
 exit(0);
}

#

port = get_kb_item("Services/nntp");
if (! port) port = 119;
if (! get_port_state(port)) exit(0);

k = string("nntp/banner/", port);
b = get_kb_item(k);
if (! b)
{
  soc = open_sock_tcp(port);
  if (! soc) exit(0);
  b = recv_line(socket: soc, length: 2048);
  close(soc);
}

# Example of banner:
# 200 Leafnode NNTP Daemon, version 1.9.32.rel running at localhost (my fqdn: www.nessus.org)

if ("Leafnode" >< b)
{
  if (ereg(string: b, pattern: "version +1\.9\.2[0-9]"))
  {
    security_warning(port: port);
  }
}
