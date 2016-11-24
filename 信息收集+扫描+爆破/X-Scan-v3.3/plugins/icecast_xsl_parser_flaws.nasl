#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(17592);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-0837", "CVE-2005-0838");
  script_bugtraq_id(12849);
  script_xref(name:"OSVDB", value:"14897");
  script_xref(name:"OSVDB", value:"14898");

  script_name(english:"Icecast XSL Parser Multiple Vulnerabilities (OF, ID)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote media streaming server is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Icecast that suffers from two
flaws in its XSL parser. 

  - A Locally-Exploitable Buffer Overflow Vulnerability
    The XSL parser does not check the size of XSL 'when', 'if',
    and 'value-of' tag values before copying them into a finite
    buffer in process memory. An attacker may potentially be
    able to exploit this vulnerability to execute arbitrary 
    code if he can have a specially-crafted XSL file placed in
    an Icecast folder.

  - An Information Disclosure Vulnerability
    The XSL parser fails to parse XSL files when the request ends
    with a dot ('.') and instead simply returns the contents.
    An attacker can exploit this to uncover sensitive information
    contained in XSL files." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/393705" );
 script_set_attribute(attribute:"see_also", value:"http://lists.xiph.org/pipermail/icecast/2005-March/008882.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for XSL parser vulnerabilities in Icecast";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8000);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8000);
if (!get_port_state(port)) exit(0);


req = http_get(port:port, item:"/status.xsl.");
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if ( ! res ) exit(0);
# If it looks like XSL, there's a problem.
if (egrep(string:res, pattern:'<xsl:template match *= *"/icestats" *>'))
    security_warning(port);
