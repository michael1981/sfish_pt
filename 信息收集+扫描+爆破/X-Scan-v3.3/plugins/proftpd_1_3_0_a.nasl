#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(27055);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-5815");
  script_bugtraq_id(20992);
  script_xref(name:"OSVDB", value:"30267");

  script_name(english:"ProFTPD src/support.c sreplace Function Remote Overflow");
  script_summary(english:"Checks version number in FTP banner");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is prone to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is using ProFTPD, a free FTP server for Unix and
Linux. 

According to its banner, the version of ProFTPD installed on the
remote host contains an off-by-one string manipulation flaw in its
'sreplace' function.  An attacker may be able to leverage this issue
to crash the affected service or execute arbitrary code remotely,
subject to the privileges under which the application operates." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2006-11/0095.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/452760/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ProFTPD version 1.3.0a or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_keys("ftp/proftpd");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("global_settings.inc");
include("ftp_func.inc");


# nb: banner checks of open-source software are prone to false-positives 
# so we only run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);


port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);


# Check the version number in the banner.
banner = get_ftp_banner(port:port);
if (banner && "ProFTPD " >< banner)
{
  # Grab the version.
  ver = NULL;

  pat = "^[0-9]{3}[ -]ProFTPD ([0-9][^ ]+) Server";
  matches = egrep(pattern:pat, string:banner);
  foreach match (split(matches))
  {
    match = chomp(match);
    item = eregmatch(pattern:pat, string:match);
    if (!isnull(item))
    {
      ver = item[1];
      break;
    }
  }

  if (ver && ver =~ "^(0\.|1\.([0-2]\.|3\.0($|rc)))")
  {
    report = string(
      "\n",
      "The banner reports this is ProFTPD version ", ver, "."
    );
    security_hole(port:port, extra:report);
  }
}
