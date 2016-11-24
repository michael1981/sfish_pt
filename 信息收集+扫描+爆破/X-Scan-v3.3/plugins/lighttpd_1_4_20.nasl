#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34332);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-1531", "CVE-2008-4298", "CVE-2008-4359", "CVE-2008-4360");
  script_bugtraq_id(28489, 31434, 31599, 31600);
  script_xref(name:"OSVDB", value:"43788");
  script_xref(name:"OSVDB", value:"48682");
  script_xref(name:"OSVDB", value:"48886");
  script_xref(name:"OSVDB", value:"48889");

  script_name(english:"lighttpd < 1.4.20 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by several issues." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of lighttpd installed on the
remote host is older than 1.4.20.  Such versions may be affected by
several issues, including :

  - SSL connections could be shut down by a remote attacker.

  - URL rewrite and redirect patterns can be circumvented by encoding.

  - mod_userdir does not sanitize URLs, which could lead to an 
    information disclosure on case insensitive file systems.
    e.g. http://example.com/~user/file.PHP would get the source code of 
    file.php, instead of running the script.

  - The server leaks memory when it processes duplicate headers. This could 
    lead to a denial of service by resource exhaustion." );
 script_set_attribute(attribute:"see_also", value:"http://trac.lighttpd.net/trac/ticket/285" );
 script_set_attribute(attribute:"see_also", value:"http://trac.lighttpd.net/trac/ticket/1720" );
 script_set_attribute(attribute:"see_also", value:"http://trac.lighttpd.net/trac/ticket/1589" );
 script_set_attribute(attribute:"see_also", value:"http://trac.lighttpd.net/trac/ticket/1774" );
 script_set_attribute(attribute:"see_also", value:"http://www.lighttpd.net/2008/9/30/1-4-20-Otherwise-the-terrorists-win" );
 script_set_attribute(attribute:"solution", value:
"Update lighttpd to version 1.4.20 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_keys("www/lighttpd");
  script_require_ports("Services/www", 80);
  exit(0);
}


# No backport for lighttpd
include("global_settings.inc");
include("http_func.inc");

if (report_paranoia < 2) exit(0);
if (!get_kb_item("www/lighttpd")) exit(0);

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

banner = get_http_banner(port: port);

srv = egrep(string: banner, icase: 1, pattern: '^Server:[ \t]*lighttpd');
if (! srv) exit(0);

srv = chomp(srv);
if (srv =~ "lighttpd/1\.([0-3]\.|4\.([0-9]|[01][0-9])([^0-9]|$))")
{
  if (report_verbosity)
  {
    ver = strstr(srv, "lighttpd/") - "lighttpd/";
    report = strcat(
      '\n',
      'lighttpd version ', ver, ' appears to be installed on the remote host\n',
      'based on the following Server response header :\n',
      '\n',
      '  ', srv, '\n'
    );
    security_warning(port: port, extra: report);
  }
  else
    security_warning(port);
}
