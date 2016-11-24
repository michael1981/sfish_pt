#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33561);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-3287", "CVE-2008-3289", "CVE-2008-3290");
  script_bugtraq_id(30306, 30308, 30313);
  script_xref(name:"OSVDB", value:"47504");
  script_xref(name:"OSVDB", value:"47506");
  script_xref(name:"OSVDB", value:"47507");
  script_xref(name:"Secunia", value:"31186");

  script_name(english:"Retrospect Backup Client Multiple Vulnerabilities (ESA-08-009)");
  script_summary(english:"Checks version of Retrospect client");

 script_set_attribute(attribute:"synopsis", value:
"The remote backup client is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the Retrospect Backup Client
installed on the remote host is affected by several vulnerabilities :

  - An error in the client may lead to memory corruption 
    and in turn a denial of service condition when 
    processing specially crafted packets, although only
    when an English client is used on a Chinese operating 
    system, which is not a supported configuration.

  - The password hash is sent over the network unencrypted,
    which could result in its disclosure.

  - A null pointer dereference error may lead to a denial
    of service condition." );
 script_set_attribute(attribute:"see_also", value:"http://www.fortiguardcenter.com/advisory/FGA-2008-16.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/494560/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/494562/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/494564/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://kb.dantz.com/article.asp?article=9692&p=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of Retrospect Client software and verify
it is at least 6.2.229 (Macintosh) / 7.6.106 (Windows) / 7.6.100 (Red
Hat Linux or Solaris)." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("retrospect_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/retrospect", 497);

  exit(0);
}


include("global_settings.inc");


port = get_kb_item("Services/retrospect");
if (!port) port = 497;
if (!get_port_state(port)) exit(0);

version = get_kb_item(string("Retrospect/", port, "/Version"));
if (!version) exit(0);


os = get_kb_item("Host/OS");
if (!os) exit(0);

fixed = "";
if ("Mac OS X" >< os) fixed = "6.2.229";
if ("Windows" >< os)  fixed = "7.6.106";
if ("Red Hat" >< os)  fixed = "7.6.100";
if ("Solaris" >< os)  fixed = "7.6.100";
if (!fixed) exit(0);


ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = split(fixed, sep:'.', keep:FALSE);
for (i=0; i<max_index(fix); i++)
  fix[i] = int(fix[i]);

for (i=0; i<max_index(ver); i++)
  if ((ver[i] < fix[i]))
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Retrospect Backup Client version ", version, " is running on\n",
        "the remote host.\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
  else if (ver[i] > fix[i])
    break;
