#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34729);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-5050");
  script_bugtraq_id(32207);
  script_xref(name:"OSVDB", value:"49832");

  script_name(english:"ClamAV < 0.94.1 get_unicode_name() Off-by-One Buffer Overflow");
  script_summary(english:"Sends a VERSION command to clamd");

 script_set_attribute(attribute:"synopsis", value:
"The remote anti-virus service is affected by a buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its version, the clamd anti-virus daemon on the remote
host is earlier than 0.94.1.  Such versions have an off-by-one heap
overflow vulnerability in the code responsible for parsing VBA project
files, specifically in the 'get_unicode_name()' function of
'libclamav/vba_extract.c', when a specific 'name' buffer is passed to
it. 

Using a specially crafted VBA project file embedded in an OLE2 Office
document, a remote attacker can trigger this vulnerability and execute
arbitrary code on the remote host with the privileges of the 'clamd'
process." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-11/0071.html" );
 script_set_attribute(attribute:"see_also", value:"http://svn.clamav.net/svn/clamav-devel/trunk/ChangeLog (look for bb#1239)" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ClamAV 0.94.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/clamd", 3310);

  exit(0);
}


include("global_settings.inc");


# nb: banner checks of open-source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);


port = get_kb_item("Services/clamd");
if (!port) port = 3310;
if (!get_port_state(port)) exit(0);


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send a VERSION command.
req = "VERSION";
send(socket:soc, data:req+'\r\n');

res = recv_line(socket:soc, length:128);
if (!strlen(res) || "ClamAV " >!< res) exit(0);


# Check the version.
version = strstr(res, "ClamAV ") - "ClamAV ";
if ("/" >< version) version = version - strstr(version, "/");

if (version =~ "^0\.(([0-9]|[0-8][0-9]|9[0-3])($|[^0-9])|94($|[^0-9.]))")
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "ClamAV version ", version, " appears to be running on the remote host based on\n",
      "the following response to a 'VERSION' command :\n",
      "\n",
      "  ", res, "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
