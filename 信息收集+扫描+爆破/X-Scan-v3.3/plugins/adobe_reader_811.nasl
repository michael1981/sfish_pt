#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(27584);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-5020");
  script_bugtraq_id(25748);
  script_xref(name:"OSVDB", value:"38068");

  script_name(english:"Adobe Reader < 8.1.1 Crafted PDF File Arbitrary Code Execution ");
  script_summary(english:"Checks version of Adobe Reader");

 script_set_attribute(attribute:"synopsis", value:
"The PDF file viewer on the remote Windows host allows execution of
arbitrary code." );
 script_set_attribute(attribute:"description", value:
"The installation of Adobe Reader on the remote host allows execution
of arbitrary code by means of a specially-crafted PDF file with a
malicious 'mailto:' link. 

Note that the issue only exists on systems running Windows XP or
Windows 2003 with Internet Explorer 7.0." );
 script_set_attribute(attribute:"see_also", value:"http://www.gnucitizen.org/blog/0day-pdf-pwns-windows" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/480080/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb07-18.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 8.1.1 or later or disable 'mailto' support as
described in the vendor advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("adobe_reader_installed.nasl", "smb_hotfixes.nasl", "smb_nativelanman.nasl");
  script_require_keys("SMB/Acroread/Version", "Host/OS/smb", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");


# Only XP and 2003 are affected.
os = get_kb_item("Host/OS/smb");
if (!os) exit(0);

if ("Windows 5.1" >< os || "Windows 5.2" >< os)
{
  # And it requires IE 7.
  ie = hotfix_check_ie_version();
  if (!isnull(ie) && ereg(pattern:"^7\.", string:ie))
  {
    ver = get_kb_item("SMB/Acroread/Version");
    if (
      ver && 
      ver =~ "^(7\.0\.|8\.(0\.|1\.0))"
    )
    {
      # If we're paranoid, don't bother checking for the workaround.
      if (report_paranoia > 1)
      {
        report = string(
          "Note that Nessus did not check whether 'mailto' support was disabled\n",
          "for Adobe Reader because of the Report Paranoia setting in effect when\n",
          "this scan was run.\n"
        );
        security_hole(port:get_kb_item("SMB/transport"), extra:report);
      }
      # Otherwise, look in the registry for the workaround.
      else 
      {
        if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

        # Connect to the appropriate share.
        name    =  kb_smb_name();
        port    =  kb_smb_transport();
        if (!get_port_state(port)) exit(0);
        login   =  kb_smb_login();
        pass    =  kb_smb_password();
        domain  =  kb_smb_domain();

        soc = open_sock_tcp(port);
        if (!soc) exit(0);

        session_init(socket:soc, hostname:name);
        rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
        if (rc != 1)
        {
          NetUseDel();
          exit(0);
        }

        # Connect to remote registry.
        hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
        if (isnull(hklm))
        {
          NetUseDel();
          exit(0);
        }

        # Get the launch permissions.
        perms = NULL;

        key = "SOFTWARE\Adobe\Acrobat Reader\7.0\FeatureLockDown\cDefaultLaunchURLPerms";
        key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
        if (!isnull(key_h))
        {
          value = RegQueryValue(handle:key_h, item:"tSchemePerms");
          if (!isnull(value)) perms = value[1];
          RegCloseKey(handle:key_h);
        }
        RegCloseKey(handle:hklm);

        # Clean up.
        NetUseDel();

        # Check perms.
        if (isnull(perms) || "|mailto:3|" >!< perms)
        {
          report = string(
            "Nessus determined that Adobe's 'mailto' support has not been disabled in\n",
            "the registry.\n"
          );
          security_hole(port, extra:report);
        }
      }
    }
  }
}
