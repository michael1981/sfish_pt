#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(17337);
  script_version ("$Revision: 1.7 $");

  script_bugtraq_id(12812);
  script_xref(name:"OSVDB", value:"14772");

  script_name(english:"IBM WebSphere Commerce ResetPassword Servlet Caching Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of IBM WebSphere Commerce that
may allow an attacker to conduct a brute-force attack against users
who have recently had their passwords invalidated in WebSphere
Commerce and uncover private information." );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21199839" );
 script_set_attribute(attribute:"solution", value:
"Apply WebSphere Commerce 5.6.0.2 fix pack or later.  If you are
running WebSphere Commerce v5.5 contact IBM product support and
request APAR IY60949." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  summary["english"] = "Checks for remote information disclosure vulnerability in IBM WebSphere Application Server";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);


# Due to the nature of this issue, we can only test based on the banner.
banner = get_http_banner(port:port);
if (
  banner &&
  egrep(string:banner, pattern:"^Server: WebSphere Application Server/([0-4]\..*|5\.([0-4]\..*|[56]\.0))")
) {
  # Check for the password reset form.
  foreach dir (make_list("", "/webapp")) {
    w = http_send_recv3(method:"GET", item:string(dir, "/commerce/servlet/emp/standard/passwordResetRequest.jsp"), port:port);
    if (isnull(w)) exit(0);
    res = w[2];

    # If it's available, there's a problem.
    if (tolower('name="logonId"') >< tolower(res)) {
      security_note(port);
      exit(0);
    }
  }
}
