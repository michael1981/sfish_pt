#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33948);
  script_version("$Revision: 1.7 $");

  script_cve_id(
    "CVE-2006-2937",
    "CVE-2006-2940",
    "CVE-2007-3108",
    "CVE-2008-1483",
    "CVE-2008-1657",
    "CVE-2008-6021"
  );
  script_bugtraq_id(28444, 30723);
  script_xref(name:"Secunia", value:"31531");
  script_xref(name:"OSVDB", value:"29260");
  script_xref(name:"OSVDB", value:"29261");
  script_xref(name:"OSVDB", value:"37055");
  script_xref(name:"OSVDB", value:"43911");
  script_xref(name:"OSVDB", value:"43745");
  script_xref(name:"OSVDB", value:"48607");

  script_name(english:"Attachmate Reflection for Secure IT UNIX server < 7.0 SP1 Multiple Vulnerabilities");
  script_summary(english:"Checks if SSH banner < 7.0.1.575");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH service is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Attachmate Reflection for Secure IT UNIX server
installed on the remote host is less than 7.0 SP1 and thus reportedly
affected by several issues :

  - There is an inherited vulnerability in OpenSSL when
    parsing malformed ASN.1 structures leading to a
    denial-of-service vulnerability (CVE-2006-2937).

  - There is an inherited vulnerability in OpenSSL when
    parsing parasitic public keys leading to a
    denial-of-service vulnerability (CVE-2006-2940).

  - There is an inherited vulnerability in OpenSSL when
    performing Montgomery multiplication, leading to a
    side-channel attack vulnerability (CVE-2007-3108).

  - There is an inherited vulnerability in OpenSSH with the
    execution of the ~/.ssh2/rc session file
    (CVE-2008-1657).

  - There is an issue with the security of forwarded X11
    connections, leading to possible hijacking.
    (CVE-2008-1483)

  - There are multiple unspecified other vulnerabilities.
    (CVE-2008-6021)" );
 script_set_attribute(attribute:"see_also", value:"http://support.attachmate.com/techdocs/2374.html#Security_Updates_in_7.0_SP1" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Attachmate Reflection for Secure IT UNIX server 7.0 SP1." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
 
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}


include("global_settings.inc");

# Don't flag Windows hosts
os = get_kb_item("Host/OS");
if (os && "Windows" >< os) exit(0);

port = get_kb_item("Services/ssh");
if (!port) port = 22;
if (!get_port_state(port)) exit(0);

# Check the version in the banner.
banner = get_kb_item("SSH/banner/" + port);
if (!banner) exit(0);
if ("ReflectionForSecureIT_" >!< banner) exit(0);

ver = strstr(banner, "ReflectionForSecureIT_") - "ReflectionForSecureIT_";
if (!ver) exit(0);

arr = split(ver, sep:".", keep:FALSE);

for ( i = 0 ; i < max_index(arr) ; i ++ )
{
 arr[i] = int(arr[i]);
}

vuln = FALSE;

if (arr[0] && arr[0] < 7) vuln = TRUE;
if (arr[0] && arr[0] == 7 && arr[1] && arr[1] == 0)
{
  if (arr[2] && arr[2] < 1) vuln = TRUE;
  if (arr[2] && arr[2] == 1 && arr[3] && arr[3] < 575) vuln = TRUE;
}

if (vuln)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "The remote Attachmate Reflection for Secure IT UNIX server returned\n",
      "the following banner :\n",
      "\n",
      "  ", banner, "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
