#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33256);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-2641");
  script_bugtraq_id(29908);
  script_xref(name:"OSVDB", value:"46548");
  script_xref(name:"Secunia", value:"30832");

  script_name(english:"Adobe Reader < 7.1.0 / 8.1.2 SU1 Unspecified JavaScript Method Handling Arbitrary Code Execution");
  script_summary(english:"Checks version of Adobe Reader / Security Updates");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that allows remote
code execution." );
 script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Windows host 
contains a flaw in the function Collab.collectEmailInfo() which 
may allow a remote attacker to crash the application and/or to 
take control of the affected system. 

To exploit this flaw, an attacker would need to trick a user on the
affected system into opening a specially crafted PDF file." );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb08-15.html" );
 script_set_attribute(attribute:"see_also", value:"http://kb.adobe.com/selfservice/viewContent.do?externalId=kb403742" );
 script_set_attribute(attribute:"solution", value:
"- If running 7.x, upgrade to version 7.1.0 or later.

- If running 8.x, upgrade to 8.1.2 if necessary and then apply Adobe's
Security Update 1 for 8.1.2." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Acroread/Version");
  script_require_ports(139,445);
  exit(0);
}

#

include("global_settings.inc");
include("smb_func.inc");

readerVer = get_kb_item("SMB/Acroread/Version");
if ( readerVer )
{
  # Regex stolen from adobe_reader_812.nasl
  if ( readerVer =~ "^([0-6]\.|7\.0|8\.(0\.|1\.[01][^0-9.]?))" )
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "The remote version of Adobe Reader is ", readerVer, ".\n"
      );
      security_hole(port:get_kb_item("SMB/transport"), extra:report);
    }
    else security_hole(port:get_kb_item("SMB/transport"));
  }
  else if ( readerVer =~ "^8\.1\.2($|[^0-9])" )
  {
    # Check HKLM\SOFTWARE\Adobe\Acrobat Reader\8.0\Installer\VersionSU
    
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
    
    hklm_handle = RegConnectRegistry (hkey:HKEY_LOCAL_MACHINE);

    if (!isnull(hklm_handle))
    {
      handle = RegOpenKey(handle:hklm_handle,
      key:"SOFTWARE\Adobe\Acrobat Reader\8.0\Installer",
      mode:MAXIMUM_ALLOWED);
      
      if (!isnull(handle))
      {
        value = RegQueryValue(handle:handle, item:"VersionSU");

        # There is no value if there are no security updates
        # There is the assumption that security updates are cumulative
        if (isnull(value))
        {
          if (report_verbosity)
          {
            report = string(
              "\n",
              "Adobe Reader version ", readerVer, " is installed on the remote host.\n"
            );
            security_hole(port:port, extra:report);
          }
          else security_hole(port:port);
        }

        RegCloseKey(handle:handle);
      }

      RegCloseKey(handle:hklm_handle);
    }

    # Clean up
    NetUseDel ();
  }
}
