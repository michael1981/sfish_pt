#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19781);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-3014");
  script_bugtraq_id(14836);
  script_xref(name:"OSVDB", value:"20007");

  script_name(english:"WEBppliance ocw_login_username Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a PHP script that is vulnerable to cross-site
scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WEBppliance, a web hosting control panel
for Windows and Linux from Ensim. 

The installed version of WEBppliance is prone to cross-site scripting
attacks because it fails to sanitize user-supplied input to the
'ocw_login_username' parameter of the login script before using it in
dynamically generated webpages." );
 script_set_attribute(attribute:"see_also", value:"http://membres.lycos.fr/newnst/exploit/Ensim_Autentification_XSS_By_ConcorDHacK.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  script_summary(english:"Checks for ocw_login_username parameter cross-site scripting vulnerability in WEBppliance");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 19638);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:19638);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert.
xss = '<script>alert("' + SCRIPT_NAME + '")</script>';
exss = urlencode(str:xss);


# Make sure the affected script exists.
w = http_send_recv3(method:"GET", item:"/webhost", port:port);
if (isnull(w)) exit(0);
res = w[2];


# If it looks like WEBppliance...
if (
  "Appliance Administrator Login" >< res &&
  "<INPUT type=text name=ocw_login_username" >< res
) {
  # Try to exploit the flaw.
  postdata = string(
    'ocw_login_username=">', exss, "&",
    "ocw_login_password=nessus"
  );
  w = http_send_recv3(method:"POST", item: "/webhost", port: port,
    content_type: "application/x-www-form-urlencoded",
    data: postdata);
  if (isnull(w)) exit(0);
  res = w[2];

  # There's a problem if we see our XSS.
  if (xss >< res) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
