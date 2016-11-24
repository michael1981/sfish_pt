#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from Tenable Network Security
#
# Ref: Bernardo Quintero of Hispasec <bernardo@hispasec.com>
#
# This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref, family change (2/03/09)
# - family change, output formatting (9/30/09)

include("compat.inc");

if(description)
{
 script_id(14597);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-1999-1078");
 script_bugtraq_id(547);
 script_xref(name:"OSVDB", value:"10356");

 script_name(english:"WS_FTP Pro Client Weak Password Encrypted");
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FTP client is using weak encryption."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of WS_FTP client installed on the remote host uses a weak
encryption method to store password information.  A local attacker
could exploit this to discover FTP passwords."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to the latest version of WS_FTP client."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N"
  );
  script_end_attributes();

 script_summary(english:"Check IPSWITCH WS_FTP version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Windows");
 script_dependencies("ws_ftp_client_overflows.nasl");
 script_require_keys("ws_ftp_client/version");
 exit(0);
}

# start script

version = get_kb_item("ws_ftp_client/version");
if ( ! version ) exit(0);

if (ereg(string:version, pattern:"^([0-5]\.[0-9]\.[0-9]|6\.0\.0\.0[^0-9])")) 
  security_note(get_kb_item("SMB/transport")); 
