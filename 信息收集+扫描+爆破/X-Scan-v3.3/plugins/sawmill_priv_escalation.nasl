#
# (C) Tenable Network Security
#



include("compat.inc");

if (description) {
  script_id(18507);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-1900", "CVE-2005-1901");
  script_bugtraq_id(13864, 13866, 13868);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"17100");
    script_xref(name:"OSVDB", value:"17101");
    script_xref(name:"OSVDB", value:"17102");
    script_xref(name:"OSVDB", value:"17103");
  }

  name["english"] = "Sawmill < 7.1.6 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a vulnerable script." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Sawmill, a weblog analysis package. 

According to its version, the installation of Sawmill on the remote
host suffers from multiple vulnerabilities :

  - An unspecified error allows an authenticated attacker to
    gain administrative access.

  - An unspecified error allows a remote attacker with no user 
    privileges in use to add a license key.

  - Multiple cross-site scripting flaws are possible against an
    administrator via the 'Add user' window as well as via the
    Licensing page." );
 script_set_attribute(attribute:"see_also", value:"http://www.networksecurity.fi/advisories/sawmill-admin.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.sawmill.net/version_history7.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sawmill 7.1.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in Sawmill < 7.1.6";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 8987);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8987);
if (!get_port_state(port)) exit(0);


# If Sawmill's running in stand-alone mode, just check the
# version number in the banner.
banner = get_http_banner(port:port);
if ( banner && "Server: Sawmill/" >< banner )
{
  if ( banner =~ "^Server: Sawmill/([0-6]\.|7\.(0|1\.[0-5][^0-9.]?))" ) 
  {
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }

  exit(0);
}


# Otherwise, look for the Sawmill CGI.
foreach dir (cgi_dirs()) {
  foreach file (make_list("sawmillcl.exe", "sawmill6cl.exe", "")) {
    # Discover whether the script exists and its version number.
    #
    # nb: the following little trick works for versions < 7.x.
    req = http_get(item:string(dir, "/", file, "?ho+{COMPLETE_VERSION}"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(1);
    pat = 'unknown command "Sawmill ([0-9].+)"<';
    matches = egrep(pattern:pat, string:res);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];

          if (ver =~ "^[0-6]\.") {
            security_warning(port);
	    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
            exit(0);
          }
          break;
        }
      }
    }

    # If it looks like Sawmill >= 7, try another little trick
    # that works with versions in the range [7.0, 7.1.7].
    if ("<title>Sawmill Error</title>" >< res) {
      postdata = string(
        "volatile.authentication_failed=true&",
        "volatile.login=true&",
        "webvars.username=%24VERSION&",
        "webvars.password=", SCRIPT_NAME, "&",
        "submit=Login"
      );
      req = string(
        "POST ", dir, "/", file, " HTTP/1.1\r\n",
        "Host: ", get_host_name(), "\r\n",
        "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "Content-Length: ", strlen(postdata), "\r\n",
        "\r\n",
        postdata
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

      pat = 'name="webvars\\.username" value="([^"]+)"';
      matches = egrep(pattern:pat, string:res);
      if (matches) {
        foreach match (split(matches)) {
          match = chomp(match);
          ver = eregmatch(pattern:pat, string:match);
          if (!isnull(ver)) {
            ver = ver[1];

            if (ver =~ "^7\.(0|1\.[0-5][^0-9.]?)") {
              security_warning(port);
	      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
              exit(0);
            }
            break;
          }
        }
      }
    }
  }
}
