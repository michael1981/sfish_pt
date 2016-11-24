#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39365);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-2035");
  script_bugtraq_id(35292);
  script_xref(name:"OSVDB", value:"54999");
  script_xref(name:"Secunia", value:"33371");

  script_name(english:"Drupal SA-CONTRIB-2009-036: Services Module Key-Based Access Bypass");
  script_summary(english:"Tries to access form to add a key");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP application that is susceptible \n",
      "to an authentication bypass."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The installation of Drupal on the remote host includes the third-party\n",
      "Services module, which offers a way to integrate external applications\n",
      "with Drupal using XMLRPC, SOAP, REST, AMF, or other such interfaces.\n",
      "It is currently configured to use a validation token, or 'key', for\n",
      "authentication and contains a flaw by which an unauthenticated remote\n",
      "attacker may view or even add keys.  Depending on access control\n",
      "checks for the underlying services exposed, an attacker may be able to\n",
      "access services which he would not normally be able to."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:string(
      "http://drupal.org/node/488004"
    )
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Upgrade to Services 6.x-0.14 or later."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:string(
      "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P"
    )
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www",80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install
install = get_kb_item(string("www/", port, "/drupal"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to pull up form for adding a key.
  url = string(dir, "/admin/build/services/keys/add");

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # There's a problem if we see the expected contents.
  if (
    'id="services-admin-keys-form"' >< res[2] ||
    'id="edit-submit" value="Create key"' >< res[2]
  )
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to verify the issue exists using the following URL :\n",
        "\n",
        " ", build_url(port:port, qs:url), "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
