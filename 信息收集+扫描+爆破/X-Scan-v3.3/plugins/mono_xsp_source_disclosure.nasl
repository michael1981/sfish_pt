#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(23934);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-6104");
  script_bugtraq_id(21687);
  script_xref(name:"OSVDB", value:"32391");

  script_name(english:"Mono XSP for ASP.NET Server Crafted Request Script Source Code Disclosure");
  script_summary(english:"Tries to retrieve ASPX source code using XSP");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Mono XSP, a lightweight web server for
hosting ASP.NET applications. 

The version of Mono XSP installed on the remote Windows host fails to
properly validate filename extensions in URLs.  A remote attacker may
be able to leverage this issue to disclose the source of scripts
hosted by the affected application using specially-crafted requests
with URL-encoded space characters." );
 script_set_attribute(attribute:"see_also", value:"http://www.eazel.es/advisory007-mono-xsp-source-disclosure-vulnerability.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/454962/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.mono-project.com/news/archive/2006/Dec-20.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mono version 1.2.2 / 1.1.13.8.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


banner = get_http_banner(port:port);
if (banner && "Server: Mono.WebServer" >< banner)
{
  files = get_kb_list(string("www/", port, "/content/extensions/aspx"));
  if (isnull(files)) files = make_list("/index.aspx", "/Default.aspx");

  n = 0;
  foreach file (files)
  {
    req = http_get(item:string(file, "%20"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    if (
      "<%@ " >< res && 
      egrep(pattern:"<%@ +language=", string:res, icase:TRUE)
    )
    {
      if (report_verbosity > 1)
        report = string(
          "Here is the source that Nessus was able to retrieve : \n",
          "\n",
          "  ", file, " :\n",
          "\n",
          res
        );
      else report = NULL;
      security_warning(port:port, extra:report); 
      exit(0);
    }
    n++;
    if (n > 20) exit(0);
  }
}
