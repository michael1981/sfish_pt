#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32323);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2008-2286","CVE-2008-2287","CVE-2008-2288","CVE-2008-2289","CVE-2008-2291");
  script_bugtraq_id(29196, 29197, 29198, 29199, 29218);
  script_xref(name:"OSVDB", value:"45313");
  script_xref(name:"OSVDB", value:"45314");
  script_xref(name:"OSVDB", value:"45316");
  script_xref(name:"OSVDB", value:"45317");
  script_xref(name:"OSVDB", value:"45318");
  script_xref(name:"Secunia", value:"30261");

  script_name(english:"Altiris Deployment Solution < 6.9.176 Multiple Vulnerabilities");
  script_summary(english:"Checks deployment server version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of the Altiris Deployment Solution installed on the remote
host reportedly is affected by several issues :

  - A SQL injection vulnerability that could allow a user
    to run arbitrary code (CVE-2008-2286).

  - A remote attacker may be able to obtain encrypted 
    Altiris Deployment Solution domain credentials without 
    authentication (CVE-2008-2291).

  - A local user could leverage a GUI tooltip to access a
    privileged command prompt (CVE-2008-2289).

  - A local user can modify or delete several registry keys
    used by the application, resulting in unauthorized 
    access to system information or disruption of service
    (CVE-2008-2288).

  - A local user with access to the install directory of
    Deployment Solution could replace application 
    components, which might then run with administrative 
    privileges on an affected system (CVE-2008-2287)." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-05/0212.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-05/0219.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-024" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-025" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-05/0194.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-05/0195.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2008.05.14a.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Altiris Deployment Solution 6.9.176 or later and update
Agents." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("altiris_deployment_server_detect.nasl");
  script_require_ports("Services/axengine", 402);
  exit(0);
}

#

include("global_settings.inc");



port = get_kb_item("Services/axengine");
if (!port) port = 402;
if (!get_port_state(port)) exit(0);


# Make sure the port is really open.
soc = open_sock_tcp(port);
if (!soc) exit(0);
close(soc);


# Check the version.
version = get_kb_item("Altiris/DSVersion/"+port);
if (!isnull(version))
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fix = split("6.9.176", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
        version = string(ver[0], ".", ver[1], ".", ver[2]);
        report = string(
          "\n",
          "Version ", version, " of the Altiris Deployment Solution is installed on\n",
          "the remote host.\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
