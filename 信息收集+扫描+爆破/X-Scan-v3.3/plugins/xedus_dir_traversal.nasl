#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# Ref: James Bercegay of the GulfTech Security Research Team
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title (9/4/09)


include("compat.inc");

if(description)
{
  script_id(14645);
  script_version("$Revision: 1.13 $");
  script_cve_id("CVE-2004-1646");
  script_bugtraq_id(11071);
  script_xref(name:"OSVDB", value:"9391");
  script_xref(name:"Secunia", value:"12418");

  script_name(english:"Xedus Webserver Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web server with a directory
traversal vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host runs Xedus Peer to Peer webserver.  This version is 
vulnerable to directory traversal.  An attacker could send a specially 
crafted URL to view arbitrary files on the system." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00047-08302004" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_summary(english:"Checks for directory traversal in Xedus");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
  script_dependencies("xedus_detect.nasl");
  script_family(english:"Peer-To-Peer File Sharing");
  script_require_ports("Services/www", 4274);
  exit(0);
}

# now the code

include("http_func.inc");

port = get_http_port(default:4274);
if ( ! get_kb_item("xedus/" + port + "/running")) exit(0);

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  buf = http_get(item:"../../../../../boot.ini", port:port);
  send(socket:soc, data:buf);
  rep = http_recv(socket:soc);
  if(egrep(pattern:"\[boot loader\]", string:rep))
    security_warning(port);
  http_close_socket(soc);
 }
}
exit(0);
