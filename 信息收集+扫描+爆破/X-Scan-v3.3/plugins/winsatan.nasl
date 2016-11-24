#
# This script was written by Julio César Hernández <jcesar@inf.uc3m.es>
#
# See the Nessus Scripts License for details
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added link to the Bugtraq message archive

include("compat.inc");

if(description)
{
 script_id(10316);
#  script_cve_id("CVE-MAP-NOMATCH");
 script_version ("$Revision: 1.16 $");
 
 script_name(english:"WinSATAN Backdoor Detection");
  script_set_attribute(
    attribute:"synopsis",
    value:"A backdoor is installed on the remote Windows host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"WinSATAN is installed.  This backdoor allows anyone to partially take
control of the remote system.  An attacker may use it to steal your
password or prevent your system from working properly."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Use regedit and find 'RegisterServiceBackUp'
in HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
The value's data is the path of the file.  If you are infected by
WinSATAN, then the registry value is named 'fs-backup.exe'."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes(); 
 
 summary["english"] = "Checks for the presence of WinSATAN";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Julio César Hernández");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl");
 script_require_ports(999);
 exit(0);
}

#
# The script code starts here
#
include('ftp_func.inc');
if(get_port_state(999))
{
soc = open_sock_tcp(999);
if(soc)
{
 if(ftp_authenticate(socket:soc, user:"uyhw6377w", pass:"bhw32qw"))security_hole(999);
 close(soc);
}
}
