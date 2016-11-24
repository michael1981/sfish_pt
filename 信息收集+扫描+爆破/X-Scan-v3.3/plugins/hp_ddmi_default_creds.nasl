#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39616);
  script_version("$Revision: 1.2 $");

  script_name(english:"HP DDMI Web Interface Default Credentials");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web application is protected using default credentials."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running HP Discovery & Dependency Mapping\n",
      "Inventory (DDMI), which is used to automate discovery and inventory\n",
      "of network devices. \n",
      "\n",
      "The remote installation of HP DDMI has at least one account\n",
      "configured using default credentials.  Knowing these, an attacker can\n",
      "gain access to the affected application, possibly even as an\n",
      "administrator."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Change the password of any reported user."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);

# Make sure it's DDM Inventory.
res = http_get_cache(item:"/", port:port);
if (isnull(res)) exit(0);

if (
  "title>HP Discovery and Dependency Mapping Inventory</title>" >!< res &&
  '<span class="loginTitle">HP Discovery and Dependency Mapping Inventory' >!< res
) exit(0);


# Try to log in.
n = 0;
creds = make_array();

users[n] = "admin";
passes[n] = "password";
n++;

users[n] = "itmanager";
passes[n] = "password";
n++;

users[n] = "itemployee";
passes[n] = "password";
n++;

users[n] = "demo";
passes[n] = "password";
n++;



# Pull up the login form.
info = "";
url = "/nm/webui/";

for (i=0; i<n; i++)
{
  user = users[i];
  pass = passes[i];

  init_cookiejar();

  req = http_mk_get_req(
    port        : port,
    item        : url, 
    add_headers : make_array(
      'Authorization',
      string('Basic ', base64(str:user+":"+pass))
    )
  );
  res = http_send_recv_req(port:port, req:req);
  if (isnull(res)) exit(0);

  # There's a problem if we've bypassed authentication.
  if ('content="0;url=/webui/customAuth.jsp"' >< res[2])
  {
    info += string(
      "\n",
      "  Username : ", user, "\n",
      "  Password : ", pass, "\n"
    );
    if (!thorough_tests) break;
  }
}


if (info)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus was able to gain access using the following information :\n",
      "\n",
      "  URL      : ", build_url(port:port, qs:url), "\n",
      # nb: info already has a leading newline
      info
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
