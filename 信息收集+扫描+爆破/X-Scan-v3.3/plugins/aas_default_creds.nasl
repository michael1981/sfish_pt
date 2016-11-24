#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38761);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-1465");
  script_bugtraq_id(34911);
  script_xref(name:"OSVDB", value:"54523");

  script_name(english:"A-A-S Application Access Server Default Admin Password");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server is protected using default credentials."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote installation of A-A-S Application Access Server is\n",
      "configured to use default credentials to control administrative\n",
      "access.  Knowing these, an attacker can gain administrative control of\n",
      "the affected application and host."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.syhunt.com/?section=resources.advisories&id=aas-multiple"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/503434/30/0/threaded"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Change the password for the 'admin' user."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("aas_detect.nasl");
  script_require_ports("Services/www", 6262);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:6262, embedded: 0);
if (!get_kb_item("www/"+port+"/aas")) exit(0);


user = "admin";
pass = "wildbat";


# Test the install.
init_cookiejar();

url = "/index.aas";
res = http_send_recv3(
  port     : port,
  method   : "GET", 
  item     : url,
  username : user,
  password : pass
);
if (
  !isnull(res) &&
  "<TITLE>Application Access Server</TITLE>" >< res[2] &&
  (
    "HREF=index.aas?job=showprocess" >< res[2] ||
    "HREF=index.aas?job=eventlog" >< res[2]
  )
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus was able to gain access using the following credentials :\n",
      "\n",
      "  URL      : ", build_url(port:port, qs:url), "\n",
      "  User     : ", user, "\n",
      "  Password : ", pass, "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
