#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32434);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-2333");
  script_bugtraq_id(29340);
  script_xref(name:"Secunia", value:"30362");
  script_xref(name:"OSVDB", value:"45611");

  script_name(english:"Barracuda Spam Firewall cgi-bin/ldap_test.cgi email Variable XSS");
  script_summary(english:"Checks firmware version");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its firmware version, the remote Barracuda Spam Firewall
device fails to filter input to the 'email' parameter of the
'/cgi-bin/ldap_test.cgi' script before using it to generate dynamic
content.  An unauthenticated remote attacker may be able to leverage
this issue to inject arbitrary HTML or script code into a user's
browser to be executed within the security context of the affected
site." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-05/0566.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.barracudanetworks.com/ns/support/tech_alert.php" );
 script_set_attribute(attribute:"solution", value:
"Either configure the device to limit access to the web management
application by IP address or update to firmware release 3.5.11.025 or
later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8000);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8000);


# Send a request for the affected file.
r = http_send_recv3(method:"GET",item:"/cgi-bin/ldap_test.cgi", port:port);
if (isnull(r)) exit(0);
res = r[2];

# Identify and check the firmware version.
firmware = "";
if ("Barracuda Firewall" >< res && "Firmware v" >< res)
{
  firmware = strstr(res, "Firmware v") - "Firmware v";
  if ("<font" >< firmware) firmware = firmware - strstr(firmware, "<font");

  if (firmware !~ "^[0-9][0-9.]+[0-9]$") firmware = "";
}

if (firmware)
{
  ver = split(firmware, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fix = split("3.5.11.025", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
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
