#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35087);
  script_version("$Revision: 1.4 $");

  script_cve_id(
    "CVE-2008-1389",
    "CVE-2008-3912",
    "CVE-2008-3913",
    "CVE-2008-3914",
    "CVE-2008-6845"
  );
  script_bugtraq_id(30994, 31051, 32752);
  script_xref(name:"OSVDB", value:"47881");
  script_xref(name:"OSVDB", value:"48237");
  script_xref(name:"OSVDB", value:"48238");
  script_xref(name:"OSVDB", value:"48239");
  script_xref(name:"OSVDB", value:"51963");

  script_name(english:"ClamAV < 0.94 Multiple Vulnerabilities");
  script_summary(english:"Sends a VERSION command to clamd");

 script_set_attribute(attribute:"synopsis", value:
"The remote anti-virus service is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"According to its version, the clamd anti-virus daemon on the remote
host is earlier than 0.94.  Such versions are affected by one or more
of the following issues :

  - A segmentation fault can occur when processing corrupted
    LZH files. (Bug #1052)

  - Invalid memory access errors in 'libclamav/chmunpack.c'
    when processing malformed CHM files may lead to a 
    crash. (Bug #1089)

  - An out-of-memory null dereference issue exists in
    'libclamav/message.c' / 'libclamav/mbox.c'. (Bug #1141)

  - Possible error path memory leaks exist in 
    'freshclam/manager.c'. (Bug #1141)

  - There is an invalid close on error path in
    'shared/tar.c'. (Bug #1141)

  - There are multiple file descriptor leaks involving the
    'error path' in 'libclamav/others.c' and 
    'libclamav/sis.c'. (Bug #1141)" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-09/0056.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-12/0111.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2008/09/03/2" );
 script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2008/09/04/13" );
 script_set_attribute(attribute:"see_also", value:"https://wwws.clamav.net/bugzilla/show_bug.cgi?id=1052" );
 script_set_attribute(attribute:"see_also", value:"https://wwws.clamav.net/bugzilla/show_bug.cgi?id=1089" );
 script_set_attribute(attribute:"see_also", value:"http://svn.clamav.net/svn/clamav-devel/trunk/ChangeLog" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?group_id=86638&release_id=623661" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ClamAV 0.94 or later." );
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

if (version =~ "^0\.(([0-9]|[0-8][0-9]|9[0-3])($|[^0-9])|94rc)")
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
