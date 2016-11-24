#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(23910);
  script_version("$Revision: 1.10 $");

  script_name(english:"Compromised Windows System (hosts File Check)");
  script_summary(english:"Checks the hosts file to determine is the system is compromised");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host may be compromised." );
 script_set_attribute(attribute:"description", value:
"The remote Windows host uses the file SYSTEM32\Drivers\etc\HOSTS to
fix the name resolution of some sites like localhost or internal
systems. 

Some viruses or spywares modify this file to prevent the antivirus or
any other security software that requires to be up to date to work
correctly. 

Nessus has found one or multiple suspicious entries in this file that
may prove the remote host is infected by a malicious program." );
 script_set_attribute(attribute:"see_also", value:"http://www.sophos.com/security/analyses/trojbagledll.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.us-cert.gov/cas/techalerts/TA04-028A.html" );
 script_set_attribute(attribute:"solution", value:
"Install / update the antivirus and remove any malicious software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");

suspicious_hosts = NULL;
suspicious_hosts[0] = "kaspersky-labs.com";
suspicious_hosts[1] = "grisoft.com";
suspicious_hosts[2] = "symantec.com";
suspicious_hosts[3] = "sophos.com";
suspicious_hosts[4] = "mcafee.com";
suspicious_hosts[5] = "symantecliveupdate.com";
suspicious_hosts[6] = "viruslist.com";
suspicious_hosts[7] = "f-secure.com";
suspicious_hosts[8] = "kaspersky.com";
suspicious_hosts[9] = "avp.com";
suspicious_hosts[10] = "networkassociates.com";
suspicious_hosts[11] = "ca.com";
suspicious_hosts[12] = "my-etrust.com";
suspicious_hosts[13] = "nai.com";
suspicious_hosts[14] = "trendmicro.com";
suspicious_hosts[15] = "microsoft.com";
suspicious_hosts[16] = "virustotal.com";
suspicious_hosts[17] = "avp.ru";
suspicious_hosts[18] = "avp.ch";
suspicious_hosts[19] = "awaps.net";

function is_suspicious_entry (line)
{
 local_var len, i, j, pattern;

 len = strlen(line);

 for (i=0;i<len;i++)
 {
  if ((line[i] != ' ') && (line[i] != '\t'))
    break;
 }

 if ((i >= len) || (line[i] == '#'))
   return FALSE;

 for (j=0; j<max_index(suspicious_hosts); j++)
 {
  pattern = '^[ \t]*[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+[ \t]+(' + suspicious_hosts[j] + "|.*\." + suspicious_hosts[j] + ").*";
  if (egrep (pattern:pattern, string:line))
  {
    return TRUE;
  }
 }
 
 return FALSE;
}


if (!get_kb_item("SMB/Registry/Enumerated"))
  exit(0);

name = kb_smb_name();
port = kb_smb_transport();
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();

if (!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

session_init(socket:soc, hostname:name);

path = hotfix_get_systemroot();

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\system32\drivers\etc\hosts", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
  exit(0);

handle = CreateFile(file: file, desired_access: GENERIC_READ, file_attributes: FILE_ATTRIBUTE_NORMAL, share_mode: FILE_SHARE_READ, create_disposition: OPEN_EXISTING);
if (isnull(handle))
{
 NetUseDel();
 exit(0);
}

fsize = GetFileSize(handle:handle);
data = NULL;

if (fsize > 0)
  data = ReadFile(handle:handle, length:fsize, offset:0);

CloseFile (handle:handle);
NetUseDel();

if ( data == NULL ) exit(0);


sfiles = NULL;

lines = split (data, sep:'\n', keep:FALSE);
foreach line (lines)
{
 if (is_suspicious_entry(line:line))
   sfiles += string (line, "\n");
}

if (sfiles)
{
 report = strcat(
      '\n',
      'Nessus found the following suspicious entries in the hosts file :\n',
      '\n',
      sfiles
 );

 security_hole(port:kb_smb_transport(), extra:report);
}
