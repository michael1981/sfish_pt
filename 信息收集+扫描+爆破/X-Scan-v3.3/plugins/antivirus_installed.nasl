#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16193);
 script_version("$Revision: 1.19 $");
 script_name(english:"Antivirus Software Check");

 script_set_attribute(attribute:"synopsis", value:
" An antivirus package is installed on the remote host." );
 script_set_attribute(attribute:"description", value:
" The remote Windows host has an antivirus installed and running.
 The remote antivirus engine and virus definitions are 
 up to date." );
 script_set_attribute(attribute:"see_also", value:" http://blog.tenablesecurity.com/2008/07/auditing-anti-v.html" );
 script_set_attribute(attribute:"see_also", value:" http://blog.tenablesecurity.com/2007/02/auditing_antivi.html" );
 script_set_attribute(attribute:"solution", value:"N/A");
 script_set_attribute(attribute:"risk_factor", value:" None" );

script_end_attributes();

 script_summary(english:"Checks that the remote host has AntiVirus installed."); 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc."); 
 script_family(english:"Windows"); 
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_full_access.nasl", "smb_enum_services.nasl", 
                     "kaspersky_installed.nasl", "mcafee_installed.nasl", "nav_installed.nasl", "panda_antivirus_installed.nasl", 
                     "trendmicro_installed.nasl", "savce_installed.nasl", "bitdefender_installed.nasl", "nod32_installed.nasl", 
                     "sophos_installed.nasl", "liveonecare_installed.nasl"); 
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport");
 script_require_ports(139, 445); 
 exit(0);
}

#

include("smb_func.inc");

#==================================================================#
# Section 1. Report                                                #
#==================================================================#

port = kb_smb_transport();

software = make_list(
  "Kaspersky",
  "McAfee",
  "Norton",
  "Panda",
  "TrendMicro",
  "SAVCE",
  "BitDefender",
  "NOD32",
  "OneCare",
  "Sophos"
);

foreach av (software) {
  if (get_kb_item("Antivirus/" + av + "/installed")) {
    info = get_kb_item("Antivirus/" + av + "/description");
    if (info) {
      report = string (
        "\n",
        info
      );
      security_note(port:port, extra:report);
    }
  }
}
