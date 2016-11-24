#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# Ref: Reported by vendor
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Changed family, formatted output (8/19/09)

include("compat.inc");

if (description)
{
 script_id(14223);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2004-0792");
 script_bugtraq_id(10938);
 script_xref(name:"OSVDB", value:"8829");  

 script_name(english:"rsync sanitize_path() Function Arbitrary File Disclosure");

 script_set_attribute(
  attribute:"synopsis",
  value:"Arbitrary files can be accessed from the remote host."
 );
 script_set_attribute(
  attribute:"description",
  value:
"A vulnerability has been reported in rsync, which can potentially be
exploited by a remote attacker to read or write arbitrary files on a
system.  Successful exploitation requires that the rsync daemon is
*not* running chrooted.

*** Since rsync does not advertise its version number
*** and since there are little details about this flaw at
*** this time, this might be a false positive"
 );
 script_set_attribute(
  attribute:"solution",
  value:"Upgrade to rsync 2.6.3 or later."
 );
 script_set_attribute(
  attribute:"cvss_vector",
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N"
 );
 script_end_attributes();

 script_summary(english:"Determines if rsync is running");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_dependencies("rsync_modules.nasl");
 script_require_ports("Services/rsync", 873);
 exit(0);
}


include('global_settings.inc');

if ( report_paranoia < 2 ) exit(0);


port = get_kb_item("Services/rsync");
if(!port)port = 873;
if(!get_port_state(port))exit(0);


welcome = get_kb_item("rsync/" + port + "/banner");
if ( ! welcome )
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 welcome = recv_line(socket:soc, length:4096);
 if(!welcome)exit(0);
}




#
# rsyncd speaking protocol 28 are not vulnerable
#

if(ereg(pattern:"@RSYNCD: (1[0-9]|2[0-8])", string:welcome))
{
 security_warning(port);
}
