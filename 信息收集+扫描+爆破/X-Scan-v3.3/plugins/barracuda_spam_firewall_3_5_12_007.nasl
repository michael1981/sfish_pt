#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35224);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2008-0971", "CVE-2008-1094");
  script_bugtraq_id(32867);
  script_xref(name:"OSVDB", value:"50709");
  script_xref(name:"Secunia", value:"33164");

  script_name(english:"Barracuda Spam Firewall < 3.5.12.007 Multiple Vulnerabilities (SQLi, XSS)");
  script_summary(english:"Grabs firmware version from cgi-bin/index.cgi");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains CGI scripts that are affected by
several issues." );
 script_set_attribute(attribute:"description", value:
"The remote Barracuda Spam Firewall device is using a firmware version
earlier than 3.5.12.007.  Such versions reportedly are affected by
several issues :

  - There is a remote SQL injection vulnerability 
    involving the 'pattern_x' parameter (where x=0...n) of 
    the 'cgi-bin/index.cgi' script when 'filter_x' is set to
    'search_count_equals'. Successful exploitation requires
    credentials. (CVE-2008-1094)

  - There are multiple cross-site scripting vulnerabilities
    due to a failure to sanitize user input when displaying
    error messages and involving multiple hidden input 
    elements. (CVE-2008-0971)" );
 script_set_attribute(attribute:"see_also", value:"http://dcsl.ul.ie/advisories/02.htm" );
 script_set_attribute(attribute:"see_also", value:"http://dcsl.ul.ie/advisories/03.htm" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-12/0174.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-12/0175.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.barracudanetworks.com/ns/support/tech_alert.php" );
 script_set_attribute(attribute:"solution", value:
"Update to firmware release 3.5.12.007 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8000);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8000);


# Grab the initial page.
url = "/cgi-bin/index.cgi";

res = http_send_recv3(port:port, method:"GET", item:url);
if (res == NULL) exit(0);


# Identify and check the firmware version.
if (
  (
    '<title>Barracuda Spam Firewall: Welcome</title>' >< res[2] ||
    'onsubmit="password.value=calcMD5(password_entry.value+enc_key.value)' >< res[2] ||
    '/header_logo.cgi" alt="Barracuda Spam Firewall"' >< res[2]
  ) &&
  'script language=javascript src="/js_functions.' >< res[2] &&
  '<input type=hidden name=enc_key value=' >< res[2]
)
{
  firmware = strstr(res[2], 'script language=javascript src="/js_functions.') - 
    'script language=javascript src="/js_functions.';
  if ('.js" type=' >< firmware) firmware = firmware - strstr(firmware, '.js" type=');

  if (firmware =~ "^[0-9][0-9.]+[0-9]$")
  {
    ver = split(firmware, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    fix = split("3.5.12.007", sep:'.', keep:FALSE);
    for (i=0; i<max_index(fix); i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(ver); i++)
      if ((ver[i] < fix[i]))
      {
        set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
        set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

        if (report_verbosity)
        {
          report = string(
            "\n",
            "The remote device is using firmware release ", firmware, ".\n"
          );
          security_warning(port:port, extra:report);
        }
        else security_warning(port);
        break;
      }
      else if (ver[i] > fix[i])
        break;
  }
}
