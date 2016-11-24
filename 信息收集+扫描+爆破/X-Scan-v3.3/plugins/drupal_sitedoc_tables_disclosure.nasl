#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32325);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-2271");
  script_bugtraq_id(29242);
  script_xref(name:"Secunia", value:"30257");
  script_xref(name:"OSVDB", value:"45170");

  script_name(english:"Site Documentation Module for Drupal Database Tables Access Content Permission Information Disclosure");
  script_summary(english:"Retrieves info from the users table");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of the Site Documentation third-party module for Drupal
installed on the remote host allows any user with 'access content'
permission to retrieve the contents of arbitrary tables in the
application's database.  An attacker could leverage this issue to
retrieve sensitive information, such as usernames, password hashes,
e-mail addresses, and active SESSION IDs." );
 script_set_attribute(attribute:"see_also", value:"http://drupal.org/node/258547" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Site Documentation 5.x-1.8 / 6.x-1.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
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
install = get_kb_item(string("www/", port, "/drupal"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Grab info from a table.
  #
  # nb: "sessions" may also be of interest.
  table = "users";

  url = string(dir, "/?q=sitedoc/table/", table);
  r = http_send_recv3(method: "GET", item:url, port:port);
  if (isnull(r)) exit(0);

  # There's a problem if we see the table's contents.
  if (
    (
      "Table Contents | " >< r[2] ||
      " Table Contents</h2>" >< r[2] 
    ) &&
    string(url, "&amp;sort=desc&amp;order=") >< r[2]
  )
  {
    if (report_verbosity)
    {
      if (get_port_transport(port) > ENCAPS_IP)
      {
        if (port == 443) url = string("https://", get_host_name(), url);
        else url = string("https://", get_host_name(), ":", port, url);
      }
      else 
      {
        if (port == 80) url = string("http://", get_host_name(), url);
        else url = string("http://", get_host_name(), ":", port, url);
      }

      report = string(
        "\n",
        "Nessus was able to obtain the contents of Drupal's user table with\n",
        "the following URL :\n",
        "\n",
        "  ", url, "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
