#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32121);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-1995");
  script_bugtraq_id(28941);
  script_xref(name:"OSVDB", value:"44624");

  script_name(english:"Sun Java System Directory Server bind-dn Remote Privilege Escalation");
  script_summary(english:"Checks the version of Sun Java Directory Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote LDAP proxy server is prone to an unauthorized access
attack." );
 script_set_attribute(attribute:"description", value:
"The version of Sun Java System Directory Proxy Server installed on the
remote host is affected by an unauthorized access vulnerability. 
Specifically, the server fails to properly classify connections in
relation to 'bind_dn' parameter.  Successful exploitation of this
issue might allow an unprivileged user to gain remote administrative
access to the system." );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-235381-1" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sun Java System Directory Server 6.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );

script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("ldap_search.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}

include("global_settings.inc");

port = get_kb_item("Services/ldap");
if (!port) port = 389;
if (!get_port_state(port)) exit(0);

ver = get_kb_item(string("LDAP/", port, "/vendorVersion"));
if (
  !isnull(ver) &&
  "Sun-Java(tm)-System-Directory/" >< ver &&
  ereg(pattern:"^Sun-Java\(tm\)-System-Directory/6\.[0-2]($|[^0-9])", string:ver)
)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "  ",ver , " is installed on the remote host.\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
