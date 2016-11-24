#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19302);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-2390");
  script_bugtraq_id(14380, 14381);
  script_xref(name:"OSVDB", value:"18270");
  script_xref(name:"OSVDB", value:"18271");

  script_name(english:"ProFTPD < 1.3.0rc2 Multiple Remote Format Strings");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is using ProFTPD, a free FTP server for Unix and
Linux. 

According to its banner, the version of ProFTPD installed on the
remote host suffers from multiple format string vulnerabilities, one
involving the 'ftpshut' utility and the other in mod_sql's
'SQLShowInfo' directive.  Exploitation of either requires involvement
on the part of a site administrator and can lead to information
disclosure, denial of service, and even a compromise of the affected
system." );
 script_set_attribute(attribute:"see_also", value:"http://www.proftpd.org/docs/RELEASE_NOTES-1.3.0rc2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ProFTPD version 1.3.0rc2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in ProFTPD < 1.3.0rc2";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("ftp_overflow.nasl");
  script_exclude_keys("ftp/false_ftp");
  script_require_keys("ftp/proftpd");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");
include("global_settings.inc");


# nb: banner checks of open-source software are prone to false-positives 
# so we only run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);



port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);


# Check the version number in the banner.
soc = open_sock_tcp(port);
if (!soc) exit(0);
banner = get_ftp_banner(port:port);
if (
  banner &&  
  banner =~ "220[ -]ProFTPD (0\..+|1\.([0-2]\..+|3\.0rc1)) Server"
) security_warning(port);
