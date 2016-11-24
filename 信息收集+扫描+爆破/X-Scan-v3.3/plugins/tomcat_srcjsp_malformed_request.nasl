#
# This script was written by David Kyger <david_kyger@symantec.com>
#
# See the Nessus Scripts License for details
#

include("compat.inc");

if(description)
{
  script_id(12123);
  script_cve_id("CVE-2002-2007");
  script_bugtraq_id(4876);
  script_xref(name:"OSVDB", value:"13303");

  script_version ("$Revision: 1.7 $");

 name["english"] = "Apache Tomcat source.jsp Arbitrary Directory Listing";
 script_name(english:name["english"]);
 
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server has an information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The source.jsp page, distributed with Apache Tomcat, will disclose
information when given a specially crafted query string.  This can
reveal information such as the web root path and directory listings. 
A remote attacker could use this information to mount further
attacks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kb.cert.org/vuls/id/116963"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Remove default files from the web server"
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
  );
  script_end_attributes();

 summary["english"] = "Checks for the Tomcat source.jsp malformed request vulnerability";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Kyger");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
 {
  pat1 = "Directory Listing";
  pat2 = "file";

  fl[0] = "/examples/jsp/source.jsp??";
  fl[1] = "/examples/jsp/source.jsp?/jsp/";

  for(i=0;fl[i];i=i+1) {
    req = http_get(item:fl[i], port:port);
    buf = http_keepalive_send_recv(port:port, data:req);
    if ( buf == NULL ) exit(0);
    if ( pat1 >< buf && pat2 >< buf) {
     report = "
The following information was obtained via a malformed request to
the web server : " + buf + "
";
	security_warning(port:port, extra:report);
	exit(0);
     }
    }
}

