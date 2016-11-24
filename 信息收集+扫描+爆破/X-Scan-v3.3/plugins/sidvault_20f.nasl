#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25935);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-4566");
  script_bugtraq_id(25460);
  script_xref(name:"OSVDB", value:"39549");

  script_name(english:"SIDVault < 2.0f LDAP Server Malformed Search Request Buffer Overflow");
  script_summary(english:"Checks version of SIDVault in web interface");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote LDAP server is vulnerable to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SIDVault, an LDAP v3 server for Windows and
Linux. 

According to its banner, the version of SIDVault on the remote host
fails to handle certain malformed search requests.  A user reportedly
can leverage this issue to crash the affected service or execute
arbitrary code on the affected system with root or SYSTEM-level
privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/477821/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4315" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SIDVault version 2.0f or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("ldap_detect.nasl", "http_version.nasl");
  script_require_ports("Services/ldap", 389, 636, "Services/www", 6680);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("kerberos_func.inc");
include("ldap_func.inc");


ldap_port = get_kb_item("Services/ldap");
if (!ldap_port)
{
  port = 389;
  soc = open_sock_tcp(port);
  if (soc)
  {
    ldap_init(socket:soc);
    bind = ldap_bind_request();
    ret = ldap_request_sendrecv(data:bind);
    if (!isnull(ret) && ret[0] == LDAP_BIND_RESPONSE) ldap_port = port;
  }
}
if (!get_port_state(ldap_port)) exit(0);


# Pull up the app's web interface.
http_port = get_http_port(default:6680);
if (!get_port_state(http_port)) exit(0);

res = http_get_cache(item:"/", port:http_port);
if (res == NULL) exit(0);


# If it looks like SIDVault...
if (
  '<title>SIDVault ' >< res &&
  '<img src="/img/-cached-sidvault' >< res
)
{
  # Extract the version number.
  ver = NULL;

  pat = "> SIDVault v([0-9]\.[0-9a-z]+) Copyright";
  matches = egrep(pattern:pat, string:res);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver))
      {
        ver = ver[1];
        break;
      }
    }
  }

  # Versions before 2.0f are affected.
  if (!isnull(ver) && ver =~ "^([01]\.|2\.0[a-e]?$)")
  {
    report = string(
      "SIDVault version ", ver, " appears to be running on the remote host.\n"
    );
    security_hole(port:ldap_port, extra:report);
  }
}

