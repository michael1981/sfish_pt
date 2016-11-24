#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33852);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2001-0051");
  script_bugtraq_id(2068);
  script_xref(name:"OSVDB", value:"9484");

  script_name(english:"Default Password (db2admin) for 'db2admin' Account on Windows");
  script_summary(english:"Tries to authenticate with default credentials");

 script_set_attribute(attribute:"synopsis", value:
"An account on the remote Windows host uses a default password." );
 script_set_attribute(attribute:"description", value:
"The 'db2admin' account on the remote Windows host uses a known
password.  This account may have been created during installation of
DB2, for use managing the application, and likely belongs to the Local
Administrators group. 

Note that while the DB2 installation no longer uses a default password
for this account, the upgrade process does not force a password change
if the 'db2admin' account exists from a previous install." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-12/0063.html" );
 script_set_attribute(attribute:"solution", value:
"Assign a different password to this account as soon as possible." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("smb_login.nasl");
  script_require_keys("SMB/name", "SMB/transport");
  script_exclude_keys("SMB/any_login");
  script_require_ports(139, 445);
  exit(0);
}

#

include("global_settings.inc");
include("smb_func.inc");


if (supplied_logins_only) exit(0);
if (get_kb_item("SMB/any_login")) exit(0);


login = "db2admin";
pass  = "db2admin";


name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(0);
domain  =  kb_smb_domain();


# Try using valid credentials.
soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
NetUseDel();
if (rc == 1) 
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Nessus was able to gain access using the following credentials :\n",
      "\n",
      "  Login    : ", login, "\n",
      "  Password : ", pass, "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
