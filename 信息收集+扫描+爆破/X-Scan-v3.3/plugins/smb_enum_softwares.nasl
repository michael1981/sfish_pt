#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(20811);
 script_version ("$Revision: 1.6 $");
 
 script_name(english:"Windows Intalled Software Enumeration (credentialed check)");
 
 script_set_attribute(attribute:"synopsis", value:"It is possible to enumerate installed software.");
 script_set_attribute(attribute:"description", value:'
This plugin lists software potentially installed on the remote host by
crawling the registry entries in :

  HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall

Note that these entries do not necessarily mean the applications are
actually installed on the remote host - they may have been left behind
by uninstallers, or the associated files may have been manually
removed.');
 script_set_attribute(attribute:"solution", value:"Remove any applications that are not compliant with your organization's 
acceptable use and security policies.");

 script_set_attribute(attribute:"risk_factor", value:"None");
 script_end_attributes();
 
 script_summary(english:"Enumerates the list of remote software");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");

port = kb_smb_transport ();

display_names = get_kb_list ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
display_vers  = get_kb_list ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayVersion");
if (isnull(display_names) && isnull(display_vers)) exit(0);

apps = make_array();
foreach display_name (keys(display_names))
{
  app = display_names[display_name];

  matches = eregmatch(string:display_name, pattern:"^(SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/.+)/DisplayName$");
  if (!isnull(matches))
  {
    display_ver = matches[1] + "/DisplayVersion";
    version = display_vers[display_ver];
  }
  else version = "";

  if (isnull(apps[app])) apps[app] = version;
  else if (apps[app] != version) apps[app] += " & " + version;
}
foreach key (keys(display_vers))
{
  matches = eregmatch(string:key, pattern:"^(SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/)(.+)/DisplayVersion$");
  if (!isnull(matches))
  {
    display_name = matches[1] + matches[2] + "/DisplayName";
    if (isnull(display_names[display_name]))
    {
      app = matches[2];
      version = display_vers[key];

      if (isnull(apps[app])) apps[app] = version;
      else if (apps[app] != version) apps[app] += " & " + version;
    }
  }
}

list = "";
foreach app (sort(keys(apps)))
{
  versions = apps[app];
  if (isnull(versions)) list += app + '\n';
  else
  {
    foreach version (sort(split(versions, sep:" & ", keep:FALSE)))
      list += string(app, "  [version ", version, "]\n");
  }
}


if(list)
{
 report = string ("\n",
		"The following software are installed on the remote host :\n\n",
		list);

 security_note(extra:report, port:port);
}
