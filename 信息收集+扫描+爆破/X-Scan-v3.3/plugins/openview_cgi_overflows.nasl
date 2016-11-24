#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(29249);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-6204");
  script_bugtraq_id(26741);
  script_xref(name:"OSVDB", value:"39529");
  script_xref(name:"OSVDB", value:"39530");
  script_xref(name:"OSVDB", value:"39531");
  script_xref(name:"OSVDB", value:"39532");

  script_name(english:"HP OpenView Network Node Manager Multiple CGI Remote Overflows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains multiple CGI scripts that allow
execution of arbitrary commands." );
 script_set_attribute(attribute:"description", value:
"The remote version of HP OpenView Network Node Manager fails to
sanitize user-supplied input to various parameters used in the
'Openview5', 'snmpview', 'ovlogin' scripts before using it. 

By sending long parameters, an attacker would be able to produce a
stack-based overflow and exploit it to execute code on the remote host
with the web server privileges. 

Bad permissions on the web server directory allow a full system
compromise." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-071.html" );
 script_set_attribute(attribute:"see_also", value:"http://support.openview.hp.com/patches/patch_index.jsp" );
 script_set_attribute(attribute:"solution", value:
"Apply patched referenced in the vendor advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple remote command execution vulnerabilities in HP OpenView Network Node Manager";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 3443);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

r = http_send_recv3(port: port, method: 'GET', item: string("/OvCgi/OpenView5.exe"));
if (isnull(r)) exit(0);

if ("<TITLE>HP OpenView Web</TITLE>" >< r[2])
{
  v = eregmatch(pattern: 'Information: \\(c\\) Copyright [0-9]+-([0-9]+) Hewlett-Packard Development Company, LP', string: r[2]);
  if (! isnull(v))
  {
     version = int(v[1]);

     if (version < 2007)
      security_hole(port, 
      		extra: '\nOpenView5.exe version is '+v[1]+'\n');
  }
}

